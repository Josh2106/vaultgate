"""Operational endpoints: liveness, readiness, metrics, JWKS."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Header, Response
from fastapi.responses import JSONResponse
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text

from app.api.deps import StateDep
from app.core.errors import NotAuthenticated, NotFound
from app.core.security import constant_time_equals
from app.schemas.auth import Jwks

router = APIRouter(tags=["system"])


@router.get("/healthz", include_in_schema=False)
async def healthz() -> dict[str, str]:
    """Liveness: the process is up and the event loop is responsive. No dependencies."""
    return {"status": "ok"}


@router.get("/readyz", include_in_schema=False)
async def readyz(state: StateDep) -> JSONResponse:
    """Readiness: dependencies reachable and not draining for shutdown."""
    checks: dict[str, str] = {}
    healthy = not state.draining
    checks["draining"] = "yes" if state.draining else "no"
    try:
        async with state.engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        checks["database"] = "ok"
    except Exception:
        checks["database"] = "error"
        healthy = False
    if state.redis is not None:
        try:
            await state.redis.ping()
            checks["redis"] = "ok"
        except Exception:
            checks["redis"] = "error"
            healthy = False
    return JSONResponse(
        {"status": "ok" if healthy else "unavailable", "checks": checks},
        status_code=200 if healthy else 503,
    )


@router.get("/metrics", include_in_schema=False)
async def metrics(
    state: StateDep, authorization: Annotated[str | None, Header()] = None
) -> Response:
    if not state.settings.metrics_enabled:
        raise NotFound()
    token = state.settings.metrics_token
    if token is not None:
        expected = f"Bearer {token.get_secret_value()}"
        if not authorization or not constant_time_equals(authorization, expected):
            raise NotAuthenticated()
    return Response(generate_latest(state.metrics.registry), media_type=CONTENT_TYPE_LATEST)


@router.get("/.well-known/jwks.json", response_model=Jwks)
async def jwks(state: StateDep) -> Jwks:
    """Public signing keys (all kids still trusted for verification)."""
    return Jwks(keys=state.tokens.keyring.jwks()["keys"])
