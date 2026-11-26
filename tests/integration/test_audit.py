from __future__ import annotations

from pathlib import Path

import httpx
import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DatabaseError

from app import cli
from app.core.config import get_settings
from app.core.permissions import Role
from app.db.models import AuditEvent
from app.services import audit
from app.state import AppState
from tests.conftest import World

pytestmark = pytest.mark.asyncio


async def _actions(state: AppState) -> list[str]:
    async with state.sessionmaker() as s:
        return list((await s.execute(select(AuditEvent.action).order_by(AuditEvent.seq))).scalars())


async def test_mutations_are_audited_and_chain_verifies(state: AppState, world: World) -> None:
    actions = await _actions(state)
    for expected in (
        "user.signup",
        "user.email_verified",
        "auth.login_succeeded",
        "org.created",
        "project.created",
        "member.added",
        "secret.created",
        "api_key.created",
    ):
        assert expected in actions, expected
    async with state.sessionmaker() as s:
        result = await audit.verify_chain(s)
    assert result.ok and result.checked == len(actions)


async def test_audit_rows_capture_request_metadata(
    client: httpx.AsyncClient, state: AppState, world: World
) -> None:
    owner = world.users[Role.OWNER]
    await client.patch(
        world.base(),
        json={"name": "Renamed"},
        headers={**owner.headers, "User-Agent": "pytest-agent", "X-Request-ID": "req-abcdef123"},
    )
    async with state.sessionmaker() as s:
        ev = (
            await s.execute(select(AuditEvent).where(AuditEvent.action == "org.updated"))
        ).scalar_one()
    assert ev.actor_type == "user" and ev.actor_id == str(owner.id)
    assert ev.ip == "203.0.113.7"
    assert ev.user_agent == "pytest-agent"
    assert ev.request_id == "req-abcdef123"
    assert ev.details == {"name": {"from": "Acme", "to": "Renamed"}}


async def test_database_rejects_update_and_delete(state: AppState, world: World) -> None:
    async with state.sessionmaker() as s:
        with pytest.raises(DatabaseError, match="append-only"):
            await s.execute(text("UPDATE audit_events SET action='x' WHERE seq=1"))
    async with state.sessionmaker() as s:
        with pytest.raises(DatabaseError, match="append-only"):
            await s.execute(text("DELETE FROM audit_events WHERE seq=1"))


async def _drop_triggers(state: AppState) -> None:
    """Simulate an attacker with DBA rights who disables the append-only guard."""
    async with state.engine.begin() as conn:
        await conn.execute(text("DROP TRIGGER audit_events_no_update"))
        await conn.execute(text("DROP TRIGGER audit_events_no_delete"))


@pytest.mark.parametrize(
    ("tamper_sql", "reason"),
    [
        ("UPDATE audit_events SET actor_id='someone-else' WHERE seq=3", "modified"),
        ("UPDATE audit_events SET details='{}' WHERE seq=5", "modified"),
        ("DELETE FROM audit_events WHERE seq=4", "missing"),
        ("UPDATE audit_events SET prev_hash='" + "f" * 64 + "' WHERE seq=6", "link"),
        ("DELETE FROM audit_events WHERE seq=(SELECT MAX(seq) FROM audit_events)", "truncation"),
    ],
)
async def test_tampering_is_detected(
    state: AppState, world: World, tamper_sql: str, reason: str
) -> None:
    await _drop_triggers(state)
    async with state.engine.begin() as conn:
        await conn.execute(text(tamper_sql))
    async with state.sessionmaker() as s:
        result = await audit.verify_chain(s)
    assert not result.ok
    assert reason in (result.reason or "")


async def test_recomputing_one_hash_is_not_enough(state: AppState, world: World) -> None:
    """Even rewriting a row *and* its hash breaks the link to the following row."""
    await _drop_triggers(state)
    async with state.sessionmaker() as s:
        ev = (await s.execute(select(AuditEvent).where(AuditEvent.seq == 2))).scalar_one()
        ev.actor_id = "forged"
        ev.hash = audit.event_hash(ev)
        await s.commit()
    async with state.sessionmaker() as s:
        result = await audit.verify_chain(s)
    assert not result.ok and result.first_bad_seq == 3


async def test_audit_endpoint_is_tenant_scoped_and_paginated(
    client: httpx.AsyncClient, world: World
) -> None:
    admin = world.users[Role.ADMIN].headers
    r = await client.get(f"{world.base()}/audit-events", params={"limit": 2}, headers=admin)
    body = r.json()
    assert len(body["items"]) == 2 and body["next_cursor"]
    seqs = [e["seq"] for e in body["items"]]
    assert seqs == sorted(seqs, reverse=True)
    r2 = await client.get(
        f"{world.base()}/audit-events",
        params={"limit": 100, "cursor": body["next_cursor"]},
        headers=admin,
    )
    assert all(e["seq"] < seqs[-1] for e in r2.json()["items"])
    # Only this org's events; signup/login events (no org) are excluded.
    all_actions = {e["action"] for e in body["items"] + r2.json()["items"]}
    assert "user.signup" not in all_actions
    r = await client.get(
        f"{world.base()}/audit-events", params={"action": "member.added"}, headers=admin
    )
    assert {e["action"] for e in r.json()["items"]} == {"member.added"}


async def test_cli_verify_audit_chain(
    state: AppState,
    world: World,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    s = state.settings
    monkeypatch.setenv("VG_DATABASE_URL", s.database_url)
    monkeypatch.setenv("VG_JWT_KEYS_DIR", str(s.jwt_keys_dir))
    monkeypatch.setenv("VG_MASTER_KEY_FILE", str(s.master_key_file))
    monkeypatch.setenv("VG_ENVIRONMENT", "test")
    get_settings.cache_clear()
    try:
        # The CLI calls asyncio.run, so execute it in a worker thread.
        import asyncio

        assert await asyncio.to_thread(cli.main, ["verify-audit-chain"]) == 0
        assert "audit chain intact" in capsys.readouterr().out
        await _drop_triggers(state)
        async with state.engine.begin() as conn:
            await conn.execute(text("UPDATE audit_events SET action='nothing' WHERE seq=2"))
        assert await asyncio.to_thread(cli.main, ["verify-audit-chain"]) == 2
        assert "TAMPERING DETECTED at seq=2" in capsys.readouterr().err
    finally:
        get_settings.cache_clear()


async def test_cli_key_management(
    state: AppState,
    world: World,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import asyncio

    s = state.settings
    monkeypatch.setenv("VG_DATABASE_URL", s.database_url)
    monkeypatch.setenv("VG_JWT_KEYS_DIR", str(s.jwt_keys_dir))
    monkeypatch.setenv("VG_MASTER_KEY_FILE", str(s.master_key_file))
    get_settings.cache_clear()
    try:
        assert cli.main(["rotate-master-key"]) == 0
        assert await asyncio.to_thread(cli.main, ["rewrap-secrets"]) == 0
        assert "re-wrapped 1 secret versions" in capsys.readouterr().out
        assert cli.main(["generate-jwt-key", "--dir", str(tmp_path / "keys")]) == 0
        assert len(list((tmp_path / "keys").glob("*.pem"))) == 1
        monkeypatch.setenv(
            "VG_DATABASE_URL", f"sqlite+aiosqlite:///{(tmp_path / 'fresh.db').as_posix()}"
        )
        get_settings.cache_clear()
        assert await asyncio.to_thread(cli.main, ["init-db"]) == 0
    finally:
        get_settings.cache_clear()
