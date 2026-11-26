"""Rate limiting and idempotency middleware."""

from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Callable

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.errors import problem_response
from app.core.idempotency import ReserveOutcome, StoredResponse
from app.core.net import client_ip, header
from app.core.ratelimit import RateLimitResult
from app.state import AppState

_EXEMPT = ("/healthz", "/readyz", "/metrics")
_AUTH_PATHS = frozenset(
    {
        "/api/v1/auth/login",
        "/api/v1/auth/login/mfa",
        "/api/v1/auth/token",
        "/api/v1/auth/signup",
        "/api/v1/auth/refresh",
        "/api/v1/auth/verify-email",
        "/api/v1/auth/password/change",
        "/api/v1/auth/2fa/enable",
        "/api/v1/auth/2fa/disable",
    }
)
_API_KEY_RE = re.compile(r"^vg_(?:live|test)_([0-9a-f]{12})_")


def _presented_credential(scope: Scope) -> str | None:
    key = header(scope, "x-api-key")
    if key:
        return key
    auth = header(scope, "authorization")
    if auth and auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


class RateLimitMiddleware:
    """Token buckets per client IP, per API key, and a strict bucket for auth endpoints."""

    def __init__(self, app: ASGIApp, state: Callable[[], AppState]) -> None:
        self.app = app
        self._state = state

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":  # lifespan/websocket: state may not exist yet
            await self.app(scope, receive, send)
            return
        state = self._state()
        path = str(scope.get("path", ""))
        if not state.settings.rate_limit_enabled or path.startswith(_EXEMPT):
            await self.app(scope, receive, send)
            return
        s = state.settings
        ip = client_ip(scope, s.trusted_proxy_hops)
        buckets: list[tuple[str, str, int, float]] = [
            ("ip", f"ip:{ip}", s.rate_limit_ip_capacity, s.rate_limit_ip_refill_per_sec)
        ]
        if path in _AUTH_PATHS and scope.get("method") == "POST":
            buckets.append(
                ("auth", f"auth:{ip}", s.rate_limit_auth_capacity, s.rate_limit_auth_refill_per_sec)
            )
        cred = _presented_credential(scope)
        if cred:
            m = _API_KEY_RE.match(cred)
            if m:
                buckets.append(
                    (
                        "api_key",
                        f"key:{m.group(1)}",
                        s.rate_limit_key_capacity,
                        s.rate_limit_key_refill_per_sec,
                    )
                )

        tightest: RateLimitResult | None = None
        for name, key, capacity, rate in buckets:
            result = await state.rate_limiter.hit(key, capacity, rate)
            if not result.allowed:
                state.metrics.rate_limited.labels(bucket=name).inc()
                retry = max(1, math.ceil(result.retry_after))
                resp = problem_response(
                    429,
                    slug="rate-limited",
                    title="Too many requests",
                    detail=f"Rate limit exceeded for {name} bucket; retry in {retry}s.",
                    headers={
                        "Retry-After": str(retry),
                        "RateLimit-Limit": str(capacity),
                        "RateLimit-Remaining": "0",
                    },
                )
                await resp(scope, receive, send)
                return
            if tightest is None or result.remaining < tightest.remaining:
                tightest = result

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start" and tightest is not None:
                headers = list(message.get("headers", []))
                headers.append((b"ratelimit-limit", str(tightest.limit).encode()))
                headers.append((b"ratelimit-remaining", str(tightest.remaining).encode()))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)


_IDEM_KEY_RE = re.compile(r"^[\x21-\x7e]{1,255}$")


class IdempotencyMiddleware:
    """Honour ``Idempotency-Key`` on POST requests (safe client retries)."""

    def __init__(self, app: ASGIApp, state: Callable[[], AppState]) -> None:
        self.app = app
        self._state = state

    async def __call__(  # noqa: PLR0911, PLR0915 - linear ASGI state machine
        self, scope: Scope, receive: Receive, send: Send
    ) -> None:
        if scope["type"] != "http" or scope.get("method") != "POST":
            await self.app(scope, receive, send)
            return
        idem_key = header(scope, "idempotency-key")
        if idem_key is None:
            await self.app(scope, receive, send)
            return
        if not _IDEM_KEY_RE.match(idem_key):
            resp = problem_response(
                400,
                slug="invalid-idempotency-key",
                title="Invalid Idempotency-Key",
                detail="Key must be 1-255 printable ASCII characters.",
            )
            await resp(scope, receive, send)
            return

        state = self._state()
        ttl = state.settings.idempotency_ttl_seconds

        # Buffer the body (already bounded by BodySizeLimitMiddleware).
        chunks: list[bytes] = []
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunks.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
        body = b"".join(chunks)

        # Keys are scoped to the caller so one tenant can never replay another's response.
        principal = hashlib.sha256((_presented_credential(scope) or "anon").encode()).hexdigest()
        store_key = hashlib.sha256(
            f"{principal}|{scope.get('path')}|{idem_key}".encode()
        ).hexdigest()
        fingerprint = hashlib.sha256(body).hexdigest()

        reservation = await state.idempotency.reserve(store_key, fingerprint, ttl)
        if reservation.outcome is ReserveOutcome.MISMATCH:
            resp = problem_response(
                422,
                slug="idempotency-key-reused",
                title="Idempotency-Key reused",
                detail="This Idempotency-Key was already used with a different request body.",
            )
            await resp(scope, receive, send)
            return
        if reservation.outcome is ReserveOutcome.IN_PROGRESS:
            resp = problem_response(
                409,
                slug="idempotency-in-progress",
                title="Request in progress",
                detail="A request with this Idempotency-Key is still being processed.",
                headers={"Retry-After": "1"},
            )
            await resp(scope, receive, send)
            return
        if reservation.outcome is ReserveOutcome.COMPLETED:
            stored = reservation.response
            assert stored is not None  # noqa: S101
            raw_headers = [(k.encode("latin-1"), v.encode("latin-1")) for k, v in stored.headers]
            raw_headers.append((b"idempotent-replayed", b"true"))
            await send(
                {"type": "http.response.start", "status": stored.status, "headers": raw_headers}
            )
            await send({"type": "http.response.body", "body": stored.body})
            return

        replayed = False

        async def replay_receive() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()

        status = 500
        captured_headers: list[tuple[str, str]] = []
        captured_body: list[bytes] = []

        async def capture_send(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = int(message["status"])
                captured_headers.extend(
                    (k.decode("latin-1"), v.decode("latin-1"))
                    for k, v in message.get("headers", [])
                )
            elif message["type"] == "http.response.body":
                captured_body.append(message.get("body", b""))
            await send(message)

        try:
            await self.app(scope, replay_receive, capture_send)
        except BaseException:
            await state.idempotency.release(store_key)
            raise
        # Do not pin transient failures: let the client retry 5xx / 429.
        if status >= 500 or status == 429:
            await state.idempotency.release(store_key)
        else:
            await state.idempotency.complete(
                store_key,
                fingerprint,
                StoredResponse(status, captured_headers, b"".join(captured_body)),
                ttl,
            )
