"""RFC 7807 (``application/problem+json``) error model.

Every error leaving the API - whether raised by a service, by FastAPI's request
validation, by a middleware, or an unhandled crash - is rendered through
:func:`problem_response` so clients only ever have to parse one error shape.
"""

from __future__ import annotations

from http import HTTPStatus
from typing import Any

import structlog
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.context import request_id_ctx

PROBLEM_CONTENT_TYPE = "application/problem+json"
PROBLEM_TYPE_PREFIX = "urn:vaultgate:problem:"

log = structlog.get_logger(__name__)


class AppError(Exception):
    """Base class for expected, client-facing errors."""

    status_code: int = 400
    slug: str = "bad-request"
    title: str = "Bad request"

    def __init__(
        self,
        detail: str | None = None,
        *,
        headers: dict[str, str] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(detail or self.title)
        self.detail = detail or self.title
        self.headers = headers or {}
        self.extra = extra or {}


class NotAuthenticated(AppError):
    status_code, slug, title = 401, "not-authenticated", "Authentication required"

    def __init__(self, detail: str | None = None, **kw: Any) -> None:
        kw.setdefault("headers", {"WWW-Authenticate": "Bearer"})
        super().__init__(detail, **kw)


class InvalidCredentials(NotAuthenticated):
    slug, title = "invalid-credentials", "Invalid credentials"


class InvalidToken(NotAuthenticated):
    slug, title = "invalid-token", "Invalid or expired token"


class MfaRequired(NotAuthenticated):
    slug, title = "mfa-required", "A second factor is required"


class PermissionDenied(AppError):
    status_code, slug, title = 403, "permission-denied", "Permission denied"


class EmailNotVerified(PermissionDenied):
    slug, title = "email-not-verified", "Email address must be verified first"


class NotFound(AppError):
    status_code, slug, title = 404, "not-found", "Resource not found"


class Conflict(AppError):
    status_code, slug, title = 409, "conflict", "Resource conflict"


class ValidationFailed(AppError):
    status_code, slug, title = 422, "validation-failed", "Request validation failed"


class PayloadTooLarge(AppError):
    status_code, slug, title = 413, "payload-too-large", "Request body too large"


class RateLimited(AppError):
    status_code, slug, title = 429, "rate-limited", "Too many requests"


class ServiceUnavailable(AppError):
    status_code, slug, title = 503, "unavailable", "Service unavailable"


def problem_body(
    status: int,
    *,
    slug: str | None = None,
    title: str | None = None,
    detail: str | None = None,
    instance: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    phrase = HTTPStatus(status).phrase if status in HTTPStatus._value2member_map_ else "Error"
    body: dict[str, Any] = {
        "type": f"{PROBLEM_TYPE_PREFIX}{slug}" if slug else "about:blank",
        "title": title or phrase,
        "status": status,
    }
    if detail:
        body["detail"] = detail
    if instance:
        body["instance"] = instance
    rid = request_id_ctx.get()
    if rid:
        body["request_id"] = rid
    if extra:
        body.update(extra)
    return body


def problem_response(
    status: int,
    *,
    slug: str | None = None,
    title: str | None = None,
    detail: str | None = None,
    instance: str | None = None,
    headers: dict[str, str] | None = None,
    extra: dict[str, Any] | None = None,
) -> JSONResponse:
    return JSONResponse(
        problem_body(status, slug=slug, title=title, detail=detail, instance=instance, extra=extra),
        status_code=status,
        headers=headers,
        media_type=PROBLEM_CONTENT_TYPE,
    )


async def _app_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, AppError)  # noqa: S101 - registered for AppError only
    return problem_response(
        exc.status_code,
        slug=exc.slug,
        title=exc.title,
        detail=exc.detail,
        instance=request.url.path,
        headers=exc.headers,
        extra=exc.extra,
    )


async def _http_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, StarletteHTTPException)  # noqa: S101
    return problem_response(
        exc.status_code,
        detail=str(exc.detail) if exc.detail else None,
        instance=request.url.path,
        headers=dict(exc.headers) if exc.headers else None,
    )


async def _validation_error_handler(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)  # noqa: S101
    errors = [
        {
            "loc": [str(p) for p in err.get("loc", ())],
            "msg": err.get("msg", ""),
            "type": err.get("type", ""),
        }
        for err in exc.errors()
    ]
    return problem_response(
        422,
        slug=ValidationFailed.slug,
        title=ValidationFailed.title,
        detail="One or more fields are invalid.",
        instance=request.url.path,
        extra={"errors": errors},
    )


async def _unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
    log.exception("unhandled_exception", path=request.url.path, exc_type=type(exc).__name__)
    return problem_response(
        500,
        slug="internal-error",
        title="Internal server error",
        detail="An unexpected error occurred. Quote the request_id when contacting support.",
        instance=request.url.path,
    )


def install_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, _app_error_handler)
    app.add_exception_handler(StarletteHTTPException, _http_error_handler)
    app.add_exception_handler(RequestValidationError, _validation_error_handler)
    app.add_exception_handler(Exception, _unhandled_error_handler)
