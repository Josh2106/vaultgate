"""Pure-ASGI middleware (no BaseHTTPMiddleware: it buffers and breaks contextvars).

Order (outermost first), wired in ``app.main``:

    RequestID -> AccessLog/Metrics -> SecurityHeaders -> CORS -> BodyLimit
              -> RateLimit -> Idempotency -> router
"""

from __future__ import annotations

import re
import time
import uuid
from collections.abc import Callable

import structlog
from fastapi import HTTPException
from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.context import request_id_ctx
from app.core.errors import problem_response
from app.core.metrics import Metrics
from app.core.net import client_ip, header

log = structlog.get_logger("vaultgate.access")

_REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._\-]{8,128}$")


class RequestIDMiddleware:
    """Accept a well-formed inbound ``X-Request-ID`` or mint one; echo it back."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        inbound = header(scope, "x-request-id")
        rid = inbound if inbound and _REQUEST_ID_RE.match(inbound) else uuid.uuid4().hex
        token = request_id_ctx.set(rid)
        structlog.contextvars.bind_contextvars(request_id=rid)

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                MutableHeaders(scope=message)["X-Request-ID"] = rid
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            structlog.contextvars.unbind_contextvars("request_id")
            request_id_ctx.reset(token)


def _route_template(scope: Scope) -> str:
    """Rebuild ``/orgs/{org_id}/...`` from the matched path params (bounded label cardinality)."""
    if scope.get("route") is None:
        return "unmatched"
    params = {str(v): k for k, v in (scope.get("path_params") or {}).items()}
    segments = str(scope.get("path", "")).split("/")
    return "/".join(f"{{{params[seg]}}}" if seg in params else seg for seg in segments)


class AccessLogMiddleware:
    """One structured log line + Prometheus sample per request (route template, not raw path)."""

    def __init__(self, app: ASGIApp, metrics: Callable[[], Metrics], trusted_hops: int) -> None:
        self.app = app
        self._metrics = metrics
        self._hops = trusted_hops

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        start = time.perf_counter()
        status = 500

        async def send_wrapper(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = int(message["status"])
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            elapsed = time.perf_counter() - start
            template = _route_template(scope)
            method = scope.get("method", "")
            m = self._metrics()
            m.http_requests.labels(method=method, route=template, status=str(status)).inc()
            m.http_latency.labels(method=method, route=template).observe(elapsed)
            log.info(
                "http_request",
                method=method,
                route=template,
                path=scope.get("path"),
                status=status,
                duration_ms=round(elapsed * 1000, 2),
                client_ip=client_ip(scope, self._hops),
            )


_DOCS_PATHS = ("/docs", "/redoc", "/openapi.json")
_API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
_DOCS_CSP = (
    "default-src 'none'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: "
    "https://fastapi.tiangolo.com; connect-src 'self'; frame-ancestors 'none'"
)


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp, *, hsts: bool) -> None:
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        is_docs = str(scope.get("path", "")).startswith(_DOCS_PATHS)

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                h = MutableHeaders(scope=message)
                h.setdefault("X-Content-Type-Options", "nosniff")
                h.setdefault("X-Frame-Options", "DENY")
                h.setdefault("Referrer-Policy", "no-referrer")
                h.setdefault("Cross-Origin-Opener-Policy", "same-origin")
                h.setdefault("Cross-Origin-Resource-Policy", "same-origin")
                h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
                h.setdefault("Content-Security-Policy", _DOCS_CSP if is_docs else _API_CSP)
                if not is_docs:
                    h.setdefault("Cache-Control", "no-store")
                if self.hsts:
                    h.setdefault(
                        "Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"
                    )
                if "server" in h:
                    del h["server"]
            await send(message)

        await self.app(scope, receive, send_wrapper)


class _BodyTooLarge(HTTPException):
    """Subclass of HTTPException so FastAPI's body parser re-raises it untouched."""

    def __init__(self, limit: int) -> None:
        super().__init__(413, detail=f"Maximum request body is {limit} bytes.")


class BodySizeLimitMiddleware:
    """Reject oversized bodies early (Content-Length) and while streaming (chunked)."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        declared = header(scope, "content-length")
        if declared is not None:
            try:
                too_big = int(declared) > self.max_bytes
            except ValueError:
                too_big = True
            if too_big:
                await self._reject(scope, receive, send)
                return

        received = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _BodyTooLarge(self.max_bytes)
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _BodyTooLarge:
            if not response_started:
                await self._reject(scope, receive, send)

    async def _reject(self, scope: Scope, receive: Receive, send: Send) -> None:
        resp = problem_response(
            413,
            slug="payload-too-large",
            title="Request body too large",
            detail=f"Maximum request body is {self.max_bytes} bytes.",
        )
        await resp(scope, receive, send)
