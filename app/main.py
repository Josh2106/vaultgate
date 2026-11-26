"""Application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from opentelemetry.sdk.trace import SpanProcessor

from app import __version__
from app.api.system import router as system_router
from app.api.v1 import api_router
from app.core.config import Settings, get_settings
from app.core.errors import install_exception_handlers
from app.core.logging import configure_logging
from app.core.telemetry import setup_tracing
from app.middleware.core import (
    AccessLogMiddleware,
    BodySizeLimitMiddleware,
    RequestIDMiddleware,
    SecurityHeadersMiddleware,
)
from app.middleware.protection import IdempotencyMiddleware, RateLimitMiddleware
from app.state import AppState

log = structlog.get_logger(__name__)

DESCRIPTION = """
**vaultgate** - multi-tenant secrets & API-key management.

Authenticate with **Authorize** (OAuth2 password flow) or an organisation API key
in the `X-API-Key` header. All errors are `application/problem+json` (RFC 7807).
"""


def create_app(
    settings: Settings | None = None,
    *,
    state: AppState | None = None,
    span_processor: SpanProcessor | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level, json=settings.log_json)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        vg = state or AppState.build(settings)
        app.state.vg = vg
        log.info(
            "startup",
            environment=settings.environment.value,
            version=__version__,
            jwt_kid=vg.tokens.keyring.active_kid,
            master_key=vg.cipher.provider.active_key_id,
        )
        try:
            yield
        finally:
            # Graceful shutdown: uvicorn has already stopped accepting connections and
            # drained in-flight requests (--timeout-graceful-shutdown); traffic was
            # steered away beforehand by the k8s preStop hook. Mark draining so any
            # late readiness probe fails, then release pools.
            vg.draining = True
            log.info("shutdown")
            await vg.aclose()

    app = FastAPI(
        title="vaultgate",
        version=__version__,
        description=DESCRIPTION,
        lifespan=lifespan,
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None,
        openapi_url=None if settings.is_production else "/openapi.json",
        swagger_ui_parameters={"persistAuthorization": False},
    )
    install_exception_handlers(app)
    app.include_router(system_router)
    app.include_router(api_router)

    def get_state() -> AppState:
        vg: AppState = app.state.vg
        return vg

    # add_middleware prepends, so register innermost first.
    app.add_middleware(IdempotencyMiddleware, state=get_state)
    app.add_middleware(RateLimitMiddleware, state=get_state)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_body_bytes)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "Idempotency-Key",
            "X-API-Key",
            "X-Request-ID",
        ],
        expose_headers=[
            "X-Request-ID",
            "RateLimit-Limit",
            "RateLimit-Remaining",
            "Retry-After",
            "Idempotent-Replayed",
        ],
        max_age=600,
    )
    app.add_middleware(SecurityHeadersMiddleware, hsts=settings.hsts_enabled)
    app.add_middleware(
        AccessLogMiddleware,
        metrics=lambda: get_state().metrics,
        trusted_hops=settings.trusted_proxy_hops,
    )
    app.add_middleware(RequestIDMiddleware)

    setup_tracing(app, settings, processor=span_processor)
    return app


def app_factory() -> FastAPI:  # pragma: no cover - uvicorn entrypoint
    """``uvicorn app.main:app_factory --factory``."""
    return create_app()
