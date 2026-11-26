from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select, update

from app.core.crypto import EnvelopeCipher, LocalKeyProvider
from app.core.permissions import Role
from app.db.models import SecretVersion
from app.services.secrets import rewrap_all
from app.state import AppState
from tests.conftest import World

pytestmark = pytest.mark.asyncio


def _secrets(world: World) -> str:
    return f"{world.base()}/projects/{world.project_id}/secrets"


async def test_secret_lifecycle(client: httpx.AsyncClient, world: World) -> None:
    h = world.users[Role.MEMBER].headers
    base = _secrets(world)
    r = await client.post(base, json={"name": "STRIPE_KEY", "value": "sk_test_1"}, headers=h)
    assert r.status_code == 201
    meta = r.json()
    assert meta["current_version"] == 1 and "value" not in meta

    r = await client.put(f"{base}/STRIPE_KEY", json={"value": "sk_test_2"}, headers=h)
    assert r.status_code == 200 and r.json()["current_version"] == 2

    r = await client.get(f"{base}/STRIPE_KEY", headers=h)
    assert r.json()["value"] == "sk_test_2" and r.json()["version"] == 2
    r = await client.get(f"{base}/STRIPE_KEY", params={"version": 1}, headers=h)
    assert r.json()["value"] == "sk_test_1"
    r = await client.get(f"{base}/STRIPE_KEY", params={"version": 9}, headers=h)
    assert r.status_code == 404

    r = await client.get(f"{base}/STRIPE_KEY/versions", headers=h)
    assert [v["version"] for v in r.json()] == [2, 1]
    assert {v["created_by_type"] for v in r.json()} == {"user"}

    r = await client.post(base, json={"name": "STRIPE_KEY", "value": "dup"}, headers=h)
    assert r.status_code == 409


async def test_soft_delete_and_restore(client: httpx.AsyncClient, world: World) -> None:
    admin = world.users[Role.ADMIN].headers
    base = _secrets(world)
    name = world.secret_name
    assert (await client.delete(f"{base}/{name}", headers=admin)).status_code == 204
    assert (await client.get(f"{base}/{name}", headers=admin)).status_code == 404
    listed = (await client.get(base, headers=admin)).json()["items"]
    assert name not in {s["name"] for s in listed}
    with_deleted = (await client.get(base, params={"include_deleted": True}, headers=admin)).json()
    assert any(s["name"] == name and s["deleted_at"] for s in with_deleted["items"])
    # Name stays reserved while soft-deleted.
    assert (
        await client.post(base, json={"name": name, "value": "x"}, headers=admin)
    ).status_code == 409
    r = await client.post(f"{base}/{name}/restore", headers=admin)
    assert r.status_code == 200 and r.json()["deleted_at"] is None
    assert (await client.post(f"{base}/{name}/restore", headers=admin)).status_code == 409
    assert (await client.get(f"{base}/{name}", headers=admin)).json()[
        "value"
    ] == "postgres://s3cr3t"


async def test_plaintext_never_hits_the_database(
    client: httpx.AsyncClient, state: AppState, world: World
) -> None:
    marker = f"needle-{uuid.uuid4().hex}"
    r = await client.post(
        _secrets(world),
        json={"name": "MARKER", "value": marker},
        headers=world.users[Role.OWNER].headers,
    )
    assert r.status_code == 201
    raw = state.settings.database_url.split("///", 1)[1]
    async with state.engine.begin() as conn:  # flush WAL into the main file
        await conn.exec_driver_sql("PRAGMA wal_checkpoint(TRUNCATE)")
    contents = await asyncio.to_thread(Path(raw).read_bytes)
    assert marker.encode() not in contents


async def test_ciphertext_transplant_is_detected(
    client: httpx.AsyncClient, state: AppState, world: World
) -> None:
    """An attacker with DB write access copies secret A's ciphertext onto secret B."""
    owner = world.users[Role.OWNER].headers
    base = _secrets(world)
    await client.post(base, json={"name": "OTHER", "value": "attacker-wants-this"}, headers=owner)
    async with state.sessionmaker() as s:
        rows = {v.secret_id: v for v in (await s.execute(select(SecretVersion))).scalars()}
        victim, source = list(rows.values())[:2]
        await s.execute(
            update(SecretVersion)
            .where(SecretVersion.id == victim.id)
            .values(ciphertext=source.ciphertext, wrapped_dek=source.wrapped_dek)
        )
        await s.commit()
    statuses = [
        (await client.get(f"{base}/{n}", headers=owner)).status_code
        for n in (world.secret_name, "OTHER")
    ]
    assert 500 in statuses  # fails closed instead of returning the wrong plaintext
    r = await client.get(
        f"{world.base()}/audit-events", params={"action": "secret.decrypt_failed"}, headers=owner
    )
    assert len(r.json()["items"]) == 1


async def test_master_key_rotation_and_rewrap(
    client: httpx.AsyncClient, state: AppState, world: World
) -> None:
    owner = world.users[Role.OWNER].headers
    url = f"{_secrets(world)}/{world.secret_name}"
    assert isinstance(state.cipher.provider, LocalKeyProvider)
    old_provider = state.cipher.provider
    old_kid = old_provider.active_key_id

    rotated = old_provider.with_new_active_key()
    state.cipher = EnvelopeCipher(rotated)
    # Old ciphertext still readable; new writes use the new key.
    assert (await client.get(url, headers=owner)).json()["value"] == "postgres://s3cr3t"
    await client.put(url, json={"value": "rotated-value"}, headers=owner)
    async with state.sessionmaker() as s:
        kids = {
            v.version: v.master_key_id for v in (await s.execute(select(SecretVersion))).scalars()
        }
    assert kids[1] == old_kid and kids[2] == rotated.active_key_id

    async with state.sessionmaker() as s:
        changed = await rewrap_all(state, s)
    assert changed >= 1
    # Drop the old key entirely: every version must still decrypt.
    state.cipher = EnvelopeCipher(
        LocalKeyProvider(
            {rotated.active_key_id: rotated._keys[rotated.active_key_id]}, rotated.active_key_id
        )
    )
    assert (await client.get(url, params={"version": 1}, headers=owner)).json()[
        "value"
    ] == "postgres://s3cr3t"
    assert (await client.get(url, headers=owner)).json()["value"] == "rotated-value"


async def test_secret_validation(client: httpx.AsyncClient, world: World) -> None:
    h = world.users[Role.OWNER].headers
    base = _secrets(world)
    for bad in ("1STARTS_WITH_DIGIT", "has space", "x" * 129, ""):
        r = await client.post(base, json={"name": bad, "value": "v"}, headers=h)
        assert r.status_code == 422, bad
    r = await client.post(base, json={"name": "BIG", "value": "x" * (64 * 1024 + 1)}, headers=h)
    assert r.status_code in (413, 422)
    r = await client.get(f"{world.base()}/projects/{uuid.uuid4()}/secrets", headers=h)
    assert r.status_code == 404


async def test_pagination_over_secrets(client: httpx.AsyncClient, world: World) -> None:
    h = world.users[Role.OWNER].headers
    base = _secrets(world)
    for i in range(7):
        await client.post(base, json={"name": f"S_{i}", "value": "v"}, headers=h)
    seen: list[str] = []
    cursor: str | None = None
    pages = 0
    while True:
        params: dict[str, str | int] = {"limit": 3}
        if cursor:
            params["cursor"] = cursor
        body = (await client.get(base, params=params, headers=h)).json()
        seen.extend(s["name"] for s in body["items"])
        pages += 1
        cursor = body["next_cursor"]
        if cursor is None:
            break
    assert pages == 3
    assert len(seen) == len(set(seen)) == 8
    r = await client.get(base, params={"cursor": "!!not-a-cursor!!"}, headers=h)
    assert r.status_code == 422
