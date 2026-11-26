"""Exhaustive role x endpoint authorisation matrix, plus tenant isolation and API keys."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from app.core.permissions import ROLE_PERMISSIONS, Permission, Role
from app.db.models import ApiKey
from app.state import AppState
from tests.conftest import World, build_world

pytestmark = pytest.mark.asyncio


@dataclass(frozen=True)
class Case:
    name: str
    method: str
    path: Callable[[World], str]
    permission: Permission
    body: Callable[[World], dict[str, Any]] | None = None


def _p(w: World) -> str:
    return f"{w.base()}/projects/{w.project_id}"


CASES = [
    Case("org.read", "GET", lambda w: w.base(), Permission.ORG_READ),
    Case(
        "org.update",
        "PATCH",
        lambda w: w.base(),
        Permission.ORG_UPDATE,
        lambda w: {"name": "Renamed"},
    ),
    Case("org.delete", "DELETE", lambda w: w.base(), Permission.ORG_DELETE),
    Case("member.list", "GET", lambda w: f"{w.base()}/members", Permission.MEMBER_READ),
    Case(
        "member.add",
        "POST",
        lambda w: f"{w.base()}/members",
        Permission.MEMBER_MANAGE,
        lambda w: {"email": w.outsider.email if w.outsider else "", "role": "viewer"},
    ),
    Case("project.list", "GET", lambda w: f"{w.base()}/projects", Permission.PROJECT_READ),
    Case("project.get", "GET", _p, Permission.PROJECT_READ),
    Case(
        "project.create",
        "POST",
        lambda w: f"{w.base()}/projects",
        Permission.PROJECT_WRITE,
        lambda w: {"name": "New", "slug": "new-proj"},
    ),
    Case(
        "project.update",
        "PATCH",
        _p,
        Permission.PROJECT_WRITE,
        lambda w: {"description": "changed"},
    ),
    Case("project.delete", "DELETE", _p, Permission.PROJECT_DELETE),
    Case("secret.list", "GET", lambda w: f"{_p(w)}/secrets", Permission.SECRET_LIST),
    Case(
        "secret.versions",
        "GET",
        lambda w: f"{_p(w)}/secrets/{w.secret_name}/versions",
        Permission.SECRET_LIST,
    ),
    Case(
        "secret.read", "GET", lambda w: f"{_p(w)}/secrets/{w.secret_name}", Permission.SECRET_READ
    ),
    Case(
        "secret.create",
        "POST",
        lambda w: f"{_p(w)}/secrets",
        Permission.SECRET_WRITE,
        lambda w: {"name": "NEW_SECRET", "value": "v"},
    ),
    Case(
        "secret.update",
        "PUT",
        lambda w: f"{_p(w)}/secrets/{w.secret_name}",
        Permission.SECRET_WRITE,
        lambda w: {"value": "v2"},
    ),
    Case(
        "secret.delete",
        "DELETE",
        lambda w: f"{_p(w)}/secrets/{w.secret_name}",
        Permission.SECRET_DELETE,
    ),
    Case("apikey.list", "GET", lambda w: f"{w.base()}/api-keys", Permission.APIKEY_READ),
    Case(
        "apikey.create",
        "POST",
        lambda w: f"{w.base()}/api-keys",
        Permission.APIKEY_MANAGE,
        lambda w: {"name": "deploy", "scopes": ["secret:read"]},
    ),
    Case(
        "apikey.revoke",
        "DELETE",
        lambda w: f"{w.base()}/api-keys/{w.api_key_id}",
        Permission.APIKEY_MANAGE,
    ),
    Case("audit.list", "GET", lambda w: f"{w.base()}/audit-events", Permission.AUDIT_READ),
]


@pytest.mark.parametrize("role", list(Role), ids=lambda r: r.value)
@pytest.mark.parametrize("case", CASES, ids=lambda c: c.name)
async def test_rbac_matrix(
    client: httpx.AsyncClient, state: AppState, role: Role, case: Case
) -> None:
    world = await build_world(client, state)
    user = world.users[role]
    r = await client.request(
        case.method,
        case.path(world),
        headers=user.headers,
        json=case.body(world) if case.body else None,
    )
    if case.permission in ROLE_PERMISSIONS[role]:
        assert 200 <= r.status_code < 300, f"{role} should be allowed {case.name}: {r.text}"
    else:
        assert r.status_code == 403, f"{role} should be denied {case.name}: {r.text}"
        assert r.json()["type"].endswith("permission-denied")


async def test_outsider_gets_404_not_403(client: httpx.AsyncClient, world: World) -> None:
    assert world.outsider is not None
    for path in (world.base(), f"{world.base()}/projects/{world.project_id}/secrets"):
        r = await client.get(path, headers=world.outsider.headers)
        assert r.status_code == 404
    r = await client.get(f"/api/v1/orgs/{uuid.uuid4()}", headers=world.outsider.headers)
    assert r.status_code == 404


async def test_project_from_other_tenant_is_invisible(
    client: httpx.AsyncClient, state: AppState
) -> None:
    a = await build_world(client, state)
    b = await build_world(client, state)
    owner_a = a.users[Role.OWNER]
    # Use org A (where caller is owner) with project id from org B: classic IDOR attempt.
    r = await client.get(
        f"{a.base()}/projects/{b.project_id}/secrets/{b.secret_name}", headers=owner_a.headers
    )
    assert r.status_code == 404


async def test_list_orgs_shows_role(client: httpx.AsyncClient, world: World) -> None:
    r = await client.get("/api/v1/orgs", headers=world.users[Role.VIEWER].headers)
    assert r.status_code == 200
    assert [o["role"] for o in r.json()["items"]] == ["viewer"]


async def _mint_key(
    client: httpx.AsyncClient, world: World, scopes: list[str], **extra: Any
) -> dict[str, Any]:
    r = await client.post(
        f"{world.base()}/api-keys",
        headers=world.users[Role.ADMIN].headers,
        json={"name": "k", "scopes": scopes, **extra},
    )
    assert r.status_code == 201, r.text
    body: dict[str, Any] = r.json()
    return body


async def test_api_key_scopes(client: httpx.AsyncClient, state: AppState, world: World) -> None:
    created = await _mint_key(client, world, ["secret:read"])
    raw = created["key"]
    assert raw.startswith("vg_test_")
    assert created["prefix"] in raw
    secret_url = f"{world.base()}/projects/{world.project_id}/secrets/{world.secret_name}"

    for headers in ({"X-API-Key": raw}, {"Authorization": f"Bearer {raw}"}):
        r = await client.get(secret_url, headers=headers)
        assert r.status_code == 200, r.text
        assert r.json()["value"] == "postgres://s3cr3t"
    # Not in scope: listing / writing.
    assert (
        await client.get(
            f"{world.base()}/projects/{world.project_id}/secrets", headers={"X-API-Key": raw}
        )
    ).status_code == 403
    assert (
        await client.put(secret_url, json={"value": "x"}, headers={"X-API-Key": raw})
    ).status_code == 403
    # API keys cannot act as users.
    assert (await client.get("/api/v1/users/me", headers={"X-API-Key": raw})).status_code == 403
    # Listing keys never exposes the secret part.
    r = await client.get(f"{world.base()}/api-keys", headers=world.users[Role.ADMIN].headers)
    assert all("key" not in k for k in r.json()["items"])
    assert any(k["last_used_at"] for k in r.json()["items"])


async def test_api_key_is_org_bound(client: httpx.AsyncClient, state: AppState) -> None:
    a = await build_world(client, state)
    b = await build_world(client, state)
    raw = (await _mint_key(client, a, ["org:read"]))["key"]
    assert (await client.get(a.base(), headers={"X-API-Key": raw})).status_code == 200
    assert (await client.get(b.base(), headers={"X-API-Key": raw})).status_code == 404


async def test_api_key_cannot_be_granted_governance_scopes(
    client: httpx.AsyncClient, world: World
) -> None:
    r = await client.post(
        f"{world.base()}/api-keys",
        headers=world.users[Role.OWNER].headers,
        json={"name": "evil", "scopes": ["member:manage", "secret:read"]},
    )
    assert r.status_code == 422
    assert "member:manage" in r.json()["detail"]


async def test_api_key_revocation_and_expiry(
    client: httpx.AsyncClient, state: AppState, world: World
) -> None:
    created = await _mint_key(client, world, ["org:read"])
    raw = created["key"]
    assert (await client.get(world.base(), headers={"X-API-Key": raw})).status_code == 200
    r = await client.delete(
        f"{world.base()}/api-keys/{created['id']}", headers=world.users[Role.ADMIN].headers
    )
    assert r.status_code == 204
    # Revoking twice is idempotent.
    assert (
        await client.delete(
            f"{world.base()}/api-keys/{created['id']}", headers=world.users[Role.ADMIN].headers
        )
    ).status_code == 204
    assert (await client.get(world.base(), headers={"X-API-Key": raw})).status_code == 401
    assert (
        await client.delete(
            f"{world.base()}/api-keys/{uuid.uuid4()}", headers=world.users[Role.ADMIN].headers
        )
    ).status_code == 404

    second = await _mint_key(client, world, ["org:read"])
    async with state.sessionmaker() as s:
        key = await s.get(ApiKey, uuid.UUID(second["id"]))
        assert key is not None
        key.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await s.commit()
    assert (await client.get(world.base(), headers={"X-API-Key": second["key"]})).status_code == 401


@pytest.mark.parametrize(
    "raw",
    [
        "vg_test_",
        "vg_test_zzzzzzzzzzzz_abc",
        "vg_test_0123456789ab_wrongsecret",
        "vg_live_0123456789ab_x" * 2,
    ],
)
async def test_malformed_or_unknown_api_keys(
    client: httpx.AsyncClient, world: World, raw: str
) -> None:
    r = await client.get(world.base(), headers={"X-API-Key": raw})
    assert r.status_code == 401


async def test_member_management_rules(
    client: httpx.AsyncClient, state: AppState, world: World
) -> None:
    admin = world.users[Role.ADMIN]
    owner = world.users[Role.OWNER]
    member_id = world.users[Role.MEMBER].id
    owner_id = owner.id
    base = f"{world.base()}/members"

    # Admin cannot mint owners or touch existing owners.
    r = await client.patch(f"{base}/{member_id}", json={"role": "owner"}, headers=admin.headers)
    assert r.status_code == 403
    r = await client.delete(f"{base}/{owner_id}", headers=admin.headers)
    assert r.status_code == 403
    # Admin can promote member -> admin.
    r = await client.patch(f"{base}/{member_id}", json={"role": "admin"}, headers=admin.headers)
    assert r.status_code == 200 and r.json()["role"] == "admin"
    # The last owner can be neither demoted nor removed.
    r = await client.patch(f"{base}/{owner_id}", json={"role": "admin"}, headers=owner.headers)
    assert r.status_code == 422
    r = await client.delete(f"{base}/{owner_id}", headers=owner.headers)
    assert r.status_code == 422
    # Owner promotes someone else, then can step down.
    r = await client.patch(f"{base}/{member_id}", json={"role": "owner"}, headers=owner.headers)
    assert r.status_code == 200
    r = await client.patch(f"{base}/{owner_id}", json={"role": "admin"}, headers=owner.headers)
    assert r.status_code == 200
    # Duplicate / unknown adds.
    r = await client.post(
        base, json={"email": admin.email, "role": "viewer"}, headers=admin.headers
    )
    assert r.status_code == 409
    r = await client.post(
        base, json={"email": "ghost@example.com", "role": "viewer"}, headers=admin.headers
    )
    assert r.status_code == 404
    # Remove a viewer.
    viewer_id = world.users[Role.VIEWER].id
    assert (await client.delete(f"{base}/{viewer_id}", headers=admin.headers)).status_code == 204
    assert (await client.delete(f"{base}/{viewer_id}", headers=admin.headers)).status_code == 404
    # Removed viewer loses access immediately.
    r = await client.get(world.base(), headers=world.users[Role.VIEWER].headers)
    assert r.status_code == 404


async def test_deleted_org_disappears(client: httpx.AsyncClient, world: World) -> None:
    owner = world.users[Role.OWNER]
    assert (await client.delete(world.base(), headers=owner.headers)).status_code == 204
    assert (await client.get(world.base(), headers=owner.headers)).status_code == 404
    r = await client.get("/api/v1/orgs", headers=owner.headers)
    assert r.json()["items"] == []


async def test_duplicate_slugs(client: httpx.AsyncClient, world: World) -> None:
    owner = world.users[Role.OWNER]
    org = (await client.get(world.base(), headers=owner.headers)).json()
    r = await client.post(
        "/api/v1/orgs", json={"name": "Dup", "slug": org["slug"]}, headers=owner.headers
    )
    assert r.status_code == 409
    r = await client.post(
        f"{world.base()}/projects", json={"name": "Dup", "slug": "backend"}, headers=owner.headers
    )
    assert r.status_code == 409
