from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from pydantic import SecretStr

from app.core.permissions import Role
from app.main import create_app
from app.state import AppState
from tests.conftest import World, make_settings, register, start_app

pytestmark = pytest.mark.asyncio


async def _client_for(
    tmp_path: Path, **overrides: object
) -> AsyncIterator[tuple[httpx.AsyncClient, AppState]]:
    app = create_app(make_settings(tmp_path, **overrides))
    async for state in start_app(app):
        transport = httpx.ASGITransport(app=app, client=("198.51.100.9", 1234))
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            yield c, state


async def test_request_id_generated_and_propagated(client: httpx.AsyncClient) -> None:
    r = await client.get("/healthz")
    assert len(r.headers["x-request-id"]) == 32
    r = await client.get("/healthz", headers={"X-Request-ID": "trace-12345678"})
    assert r.headers["x-request-id"] == "trace-12345678"
    # Malicious / malformed IDs are replaced, not reflected (header/log injection).
    r = await client.get("/healthz", headers={"X-Request-ID": "bad id\twith junk"})
    assert r.headers["x-request-id"] != "bad id\twith junk"


async def test_problem_details_include_request_id(client: httpx.AsyncClient) -> None:
    r = await client.get("/api/v1/does-not-exist", headers={"X-Request-ID": "rid-for-404s"})
    assert r.status_code == 404
    assert r.headers["content-type"] == "application/problem+json"
    body = r.json()
    assert body["status"] == 404 and body["request_id"] == "rid-for-404s"
    assert body["type"] == "about:blank"


async def test_security_headers(client: httpx.AsyncClient) -> None:
    r = await client.get("/healthz")
    h = r.headers
    assert h["x-content-type-options"] == "nosniff"
    assert h["x-frame-options"] == "DENY"
    assert h["referrer-policy"] == "no-referrer"
    assert "default-src 'none'" in h["content-security-policy"]
    assert h["cache-control"] == "no-store"
    assert "strict-transport-security" not in h  # disabled in test settings
    assert "server" not in h
    docs = await client.get("/docs")
    assert "cdn.jsdelivr.net" in docs.headers["content-security-policy"]


async def test_hsts_when_enabled(tmp_path: Path) -> None:
    async for c, _ in _client_for(tmp_path, hsts_enabled=True):
        r = await c.get("/healthz")
        assert r.headers["strict-transport-security"].startswith("max-age=63072000")


async def test_cors_allows_only_listed_origins(client: httpx.AsyncClient) -> None:
    preflight = {
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Authorization,Content-Type",
    }
    ok = await client.options(
        "/api/v1/auth/login", headers={"Origin": "https://app.example.com", **preflight}
    )
    assert ok.status_code == 200
    assert ok.headers["access-control-allow-origin"] == "https://app.example.com"
    bad = await client.options(
        "/api/v1/auth/login", headers={"Origin": "https://evil.example", **preflight}
    )
    assert bad.status_code == 400
    assert "access-control-allow-origin" not in bad.headers


async def test_body_size_limit_content_length(client: httpx.AsyncClient, state: AppState) -> None:
    big = b"{" + b" " * (state.settings.max_body_bytes + 10) + b"}"
    r = await client.post(
        "/api/v1/auth/login", content=big, headers={"Content-Type": "application/json"}
    )
    assert r.status_code == 413
    assert r.headers["content-type"] == "application/problem+json"


async def test_body_size_limit_chunked(client: httpx.AsyncClient, state: AppState) -> None:
    async def gen() -> AsyncIterator[bytes]:
        for _ in range(10):
            yield b" " * (state.settings.max_body_bytes // 4)

    r = await client.post(
        "/api/v1/auth/login", content=gen(), headers={"Content-Type": "application/json"}
    )
    assert r.status_code == 413
    r = await client.post(
        "/api/v1/auth/signup",
        content=gen(),
        headers={"Content-Type": "application/json", "Idempotency-Key": "k1"},
    )
    assert r.status_code == 413


async def test_rate_limit_auth_bucket(tmp_path: Path) -> None:
    async for c, state in _client_for(
        tmp_path, rate_limit_auth_capacity=3, rate_limit_auth_refill_per_sec=0.01
    ):
        body = {"email": "x@example.com", "password": "whatever-password"}
        codes = [(await c.post("/api/v1/auth/login", json=body)).status_code for _ in range(5)]
        assert codes == [401, 401, 401, 429, 429]
        r = await c.post("/api/v1/auth/login", json=body)
        assert r.headers["content-type"] == "application/problem+json"
        assert int(r.headers["retry-after"]) >= 1
        assert r.headers["ratelimit-remaining"] == "0"
        # Non-auth endpoints use the (larger) general bucket and are unaffected.
        assert (await c.get("/.well-known/jwks.json")).status_code == 200
        metrics = (await c.get("/metrics")).text
        assert 'vaultgate_rate_limited_total{bucket="auth"}' in metrics
        assert state.settings.rate_limit_enabled


async def test_rate_limit_per_ip_and_headers(tmp_path: Path) -> None:
    async for c, _ in _client_for(
        tmp_path, rate_limit_ip_capacity=2, rate_limit_ip_refill_per_sec=0.01
    ):
        r1 = await c.get("/.well-known/jwks.json")
        assert r1.headers["ratelimit-limit"] == "2"
        assert r1.headers["ratelimit-remaining"] == "1"
        await c.get("/.well-known/jwks.json")
        assert (await c.get("/.well-known/jwks.json")).status_code == 429
        assert (await c.get("/healthz")).status_code == 200  # probes are exempt


async def test_rate_limit_per_api_key(tmp_path: Path) -> None:
    async for c, _ in _client_for(
        tmp_path, rate_limit_key_capacity=2, rate_limit_key_refill_per_sec=0.01
    ):
        h = {"X-API-Key": "vg_test_0123456789ab_fake"}
        codes = [(await c.get("/.well-known/jwks.json", headers=h)).status_code for _ in range(3)]
        assert codes == [200, 200, 429]
        # A different key has its own bucket.
        h2 = {"Authorization": "Bearer vg_test_ba9876543210_fake"}
        assert (await c.get("/.well-known/jwks.json", headers=h2)).status_code == 200


async def test_idempotent_post_replays(client: httpx.AsyncClient, world: World) -> None:
    h = {**world.users[Role.OWNER].headers, "Idempotency-Key": "create-proj-1"}
    url = f"{world.base()}/projects"
    body = {"name": "Payments", "slug": "payments"}
    first = await client.post(url, json=body, headers=h)
    second = await client.post(url, json=body, headers=h)
    assert first.status_code == second.status_code == 201
    assert first.json() == second.json()
    assert second.headers["idempotent-replayed"] == "true"
    assert "idempotent-replayed" not in first.headers
    projects = (await client.get(url, headers=world.users[Role.OWNER].headers)).json()["items"]
    assert [p["slug"] for p in projects].count("payments") == 1

    # Same key, different payload -> 422.
    r = await client.post(url, json={"name": "Other", "slug": "other"}, headers=h)
    assert r.status_code == 422 and r.json()["type"].endswith("idempotency-key-reused")
    # Same key from a different principal is a different key namespace.
    h_admin = {**world.users[Role.ADMIN].headers, "Idempotency-Key": "create-proj-1"}
    r = await client.post(url, json={"name": "Other", "slug": "other"}, headers=h_admin)
    assert r.status_code == 201


async def test_idempotency_does_not_pin_errors_and_validates_keys(
    client: httpx.AsyncClient, state: AppState
) -> None:
    r = await client.post("/api/v1/auth/login", json={}, headers={"Idempotency-Key": "a" * 300})
    assert r.status_code == 400
    # 4xx responses are stored (they are deterministic for the same input).
    r1 = await client.post(
        "/api/v1/auth/login",
        json={"email": "no@example.com", "password": "x"},
        headers={"Idempotency-Key": "login-1"},
    )
    r2 = await client.post(
        "/api/v1/auth/login",
        json={"email": "no@example.com", "password": "x"},
        headers={"Idempotency-Key": "login-1"},
    )
    assert r1.status_code == r2.status_code == 401
    assert r2.headers["idempotent-replayed"] == "true"


async def test_idempotency_in_progress_conflict(client: httpx.AsyncClient, state: AppState) -> None:
    from app.core.idempotency import ReserveOutcome

    gate = asyncio.Event()
    original = state.idempotency.complete

    async def slow_complete(*args: object, **kwargs: object) -> None:
        await gate.wait()
        await original(*args, **kwargs)  # type: ignore[arg-type]

    state.idempotency.complete = slow_complete  # type: ignore[method-assign]
    h = {"Idempotency-Key": "concurrent-1"}
    body = {"email": "c@example.com", "password": "x"}
    first = asyncio.create_task(client.post("/api/v1/auth/login", json=body, headers=h))
    await asyncio.sleep(0.3)
    second = await client.post("/api/v1/auth/login", json=body, headers=h)
    assert second.status_code == 409
    gate.set()
    assert (await first).status_code == 401
    assert ReserveOutcome.IN_PROGRESS.value == "in_progress"


async def test_validation_errors_are_problem_json(client: httpx.AsyncClient) -> None:
    r = await client.post("/api/v1/auth/login", json={"email": "not-an-email"})
    assert r.status_code == 422
    body = r.json()
    assert body["type"] == "urn:vaultgate:problem:validation-failed"
    locs = {tuple(e["loc"]) for e in body["errors"]}
    assert ("body", "email") in locs and ("body", "password") in locs


async def test_unhandled_errors_are_masked(tmp_path: Path) -> None:
    app = create_app(make_settings(tmp_path))

    @app.get("/boom")
    async def boom() -> None:
        raise RuntimeError("secret internal detail")

    async for _ in start_app(app):
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            r = await c.get("/boom")
    assert r.status_code == 500
    assert "secret internal detail" not in r.text
    assert r.json()["type"].endswith("internal-error")


async def test_health_and_readiness(client: httpx.AsyncClient, state: AppState) -> None:
    assert (await client.get("/healthz")).json() == {"status": "ok"}
    r = await client.get("/readyz")
    assert r.status_code == 200 and r.json()["checks"]["database"] == "ok"
    state.draining = True
    r = await client.get("/readyz")
    assert r.status_code == 503 and r.json()["checks"]["draining"] == "yes"
    state.draining = False


async def test_readiness_reports_db_failure(client: httpx.AsyncClient, state: AppState) -> None:
    await state.engine.dispose()
    original = state.engine
    from sqlalchemy.ext.asyncio import create_async_engine

    state.engine = create_async_engine("sqlite+aiosqlite:///Z:/nonexistent/dir/x.db")
    try:
        r = await client.get("/readyz")
        assert r.status_code == 503 and r.json()["checks"]["database"] == "error"
    finally:
        await state.engine.dispose()
        state.engine = original


async def test_metrics_endpoint(client: httpx.AsyncClient, state: AppState, world: World) -> None:
    text = (await client.get("/metrics")).text
    assert "vaultgate_http_requests_total" in text
    assert 'route="/api/v1/orgs/{org_id}/projects"' in text  # templated, low cardinality
    assert 'vaultgate_auth_logins_total{outcome="success"}' in text
    state.settings.metrics_token = SecretStr("scrape-me")
    assert (await client.get("/metrics")).status_code == 401
    assert (
        await client.get("/metrics", headers={"Authorization": "Bearer scrape-me"})
    ).status_code == 200
    state.settings.metrics_enabled = False
    assert (await client.get("/metrics")).status_code == 404


async def test_opentelemetry_spans(tmp_path: Path) -> None:
    exporter = InMemorySpanExporter()
    app = create_app(
        make_settings(tmp_path, otel_enabled=True), span_processor=SimpleSpanProcessor(exporter)
    )
    async for state in start_app(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            await register(c, state)
    names = {s.name for s in exporter.get_finished_spans()}
    assert any("/api/v1/auth/login" in n for n in names), names


async def test_redis_backends_wire_up(tmp_path: Path) -> None:
    import fakeredis

    from app.core.idempotency import RedisIdempotencyStore
    from app.core.ratelimit import RedisRateLimiter

    redis = fakeredis.FakeAsyncRedis()
    app = create_app(
        make_settings(tmp_path, rate_limit_auth_capacity=2, rate_limit_auth_refill_per_sec=0.01)
    )
    built = AppState.build(
        app_settings := make_settings(
            tmp_path, rate_limit_auth_capacity=2, rate_limit_auth_refill_per_sec=0.01
        ),
        redis=redis,
    )
    assert isinstance(built.rate_limiter, RedisRateLimiter)
    assert isinstance(built.idempotency, RedisIdempotencyStore)
    app = create_app(app_settings, state=built)
    async for state in start_app(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
            assert (await c.get("/readyz")).json()["checks"]["redis"] == "ok"
            body = {"email": "r@example.com", "password": "x"}
            codes = [(await c.post("/api/v1/auth/login", json=body)).status_code for _ in range(3)]
            assert codes == [401, 401, 429]
        assert state.redis is redis


async def test_lifespan_through_full_middleware_stack(tmp_path: Path) -> None:
    """Uvicorn sends lifespan events through every middleware before state exists."""
    app = create_app(make_settings(tmp_path))
    inbox = [{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}]
    sent: list[str] = []

    async def receive() -> dict[str, str]:
        return inbox.pop(0)

    async def send(message: dict[str, str]) -> None:
        sent.append(message["type"])

    await app({"type": "lifespan", "asgi": {"version": "3.0"}, "state": {}}, receive, send)  # type: ignore[arg-type]
    assert sent == ["lifespan.startup.complete", "lifespan.shutdown.complete"]
