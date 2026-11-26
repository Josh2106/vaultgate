from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI

from app.core.config import EmailBackend, Environment, Settings
from app.core.email import MemoryEmailProvider
from app.core.permissions import Role
from app.db.base import Base
from app.main import create_app
from app.state import AppState

PASSWORD = "Correct-Horse-42!"


def make_settings(tmp_path: Path, **overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "environment": Environment.TEST,
        "database_url": f"sqlite+aiosqlite:///{(tmp_path / 'test.db').as_posix()}",
        "jwt_keys_dir": tmp_path / "jwt",
        "master_key_file": tmp_path / "master-keys.json",
        "argon2_time_cost": 1,
        "argon2_memory_cost_kib": 1024,
        "argon2_parallelism": 1,
        "email_backend": EmailBackend.MEMORY,
        "log_json": True,
        "log_level": "WARNING",
        "rate_limit_ip_capacity": 10_000,
        "rate_limit_auth_capacity": 10_000,
        "rate_limit_key_capacity": 10_000,
        "cors_origins": ["https://app.example.com"],
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return make_settings(tmp_path)


async def start_app(app: FastAPI) -> AsyncIterator[AppState]:
    async with app.router.lifespan_context(app):
        state: AppState = app.state.vg
        async with state.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        yield state


@pytest.fixture
async def app(settings: Settings) -> AsyncIterator[FastAPI]:
    application = create_app(settings)
    async for _ in start_app(application):
        yield application


@pytest.fixture
def state(app: FastAPI) -> AppState:
    vg: AppState = app.state.vg
    return vg


@pytest.fixture
async def client(app: FastAPI) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=app, client=("203.0.113.7", 50000))
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


def outbox(state: AppState) -> MemoryEmailProvider:
    assert isinstance(state.email, MemoryEmailProvider)
    return state.email


def last_token_for(state: AppState, email: str) -> str:
    for msg in reversed(outbox(state).outbox):
        if msg.to == email.lower() and "token to /api/v1/auth/verify-email: " in msg.body:
            return msg.body.rsplit(": ", 1)[1].strip()
    raise AssertionError(f"no verification email for {email}")


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@dataclass
class UserHandle:
    email: str
    access: str
    refresh: str
    id: uuid.UUID

    @property
    def headers(self) -> dict[str, str]:
        return bearer(self.access)


async def register(
    client: httpx.AsyncClient,
    state: AppState,
    email: str | None = None,
    password: str = PASSWORD,
    *,
    verify: bool = True,
) -> UserHandle:
    email = email or f"user-{uuid.uuid4().hex[:10]}@example.com"
    r = await client.post(
        "/api/v1/auth/signup", json={"email": email, "password": password, "full_name": "Test"}
    )
    assert r.status_code == 202, r.text
    if verify:
        r = await client.post(
            "/api/v1/auth/verify-email", json={"token": last_token_for(state, email)}
        )
        assert r.status_code == 204, r.text
    r = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    body = r.json()
    me = await client.get("/api/v1/users/me", headers=bearer(body["access_token"]))
    return UserHandle(
        email, body["access_token"], body["refresh_token"], uuid.UUID(me.json()["id"])
    )


@dataclass
class World:
    """An org with one user per role, a project, a secret and an API key."""

    org_id: str
    project_id: str
    users: dict[Role, UserHandle] = field(default_factory=dict)
    outsider: UserHandle | None = None
    secret_name: str = "DATABASE_URL"
    api_key_id: str = ""

    def base(self) -> str:
        return f"/api/v1/orgs/{self.org_id}"


async def build_world(client: httpx.AsyncClient, state: AppState) -> World:
    owner = await register(client, state)
    r = await client.post(
        "/api/v1/orgs",
        json={"name": "Acme", "slug": f"acme-{uuid.uuid4().hex[:6]}"},
        headers=owner.headers,
    )
    assert r.status_code == 201, r.text
    org_id = r.json()["id"]
    r = await client.post(
        f"/api/v1/orgs/{org_id}/projects",
        json={"name": "Backend", "slug": "backend"},
        headers=owner.headers,
    )
    assert r.status_code == 201, r.text
    project_id = r.json()["id"]
    world = World(org_id=org_id, project_id=project_id, users={Role.OWNER: owner})
    for role in (Role.ADMIN, Role.MEMBER, Role.VIEWER):
        u = await register(client, state)
        r = await client.post(
            f"{world.base()}/members", json={"email": u.email, "role": role}, headers=owner.headers
        )
        assert r.status_code == 201, r.text
        world.users[role] = u
    r = await client.post(
        f"{world.base()}/projects/{project_id}/secrets",
        json={"name": world.secret_name, "value": "postgres://s3cr3t"},
        headers=owner.headers,
    )
    assert r.status_code == 201, r.text
    r = await client.post(
        f"{world.base()}/api-keys",
        json={"name": "ci", "scopes": ["secret:read"]},
        headers=owner.headers,
    )
    assert r.status_code == 201, r.text
    world.api_key_id = r.json()["id"]
    world.outsider = await register(client, state)
    return world


@pytest.fixture
async def world(client: httpx.AsyncClient, state: AppState) -> World:
    return await build_world(client, state)
