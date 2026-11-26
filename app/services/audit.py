"""Tamper-evident audit trail.

Every mutating operation calls :func:`record` *inside the same transaction* as
the change it describes, so either both commit or neither does - there is no
window where an action happened but was not logged.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import utcnow
from app.db.models import GENESIS_HASH, AuditChainHead, AuditEvent
from app.services.context import RequestContext


def canonical_payload(
    *,
    seq: int,
    ts: datetime,
    actor_type: str,
    actor_id: str | None,
    org_id: uuid.UUID | None,
    action: str,
    target_type: str | None,
    target_id: str | None,
    ip: str | None,
    user_agent: str | None,
    request_id: str | None,
    details: dict[str, Any],
) -> bytes:
    doc = {
        "seq": seq,
        "ts": ts.isoformat(timespec="microseconds"),
        "actor_type": actor_type,
        "actor_id": actor_id,
        "org_id": str(org_id) if org_id else None,
        "action": action,
        "target_type": target_type,
        "target_id": target_id,
        "ip": ip,
        "user_agent": user_agent,
        "request_id": request_id,
        "details": details,
    }
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def chain_hash(prev_hash: str, payload: bytes) -> str:
    return hashlib.sha256(prev_hash.encode() + b"|" + payload).hexdigest()


def event_hash(ev: AuditEvent) -> str:
    return chain_hash(
        ev.prev_hash,
        canonical_payload(
            seq=ev.seq,
            ts=ev.ts,
            actor_type=ev.actor_type,
            actor_id=ev.actor_id,
            org_id=ev.org_id,
            action=ev.action,
            target_type=ev.target_type,
            target_id=ev.target_id,
            ip=ev.ip,
            user_agent=ev.user_agent,
            request_id=ev.request_id,
            details=ev.details,
        ),
    )


async def record(
    session: AsyncSession,
    ctx: RequestContext,
    action: str,
    *,
    org_id: uuid.UUID | None = None,
    target_type: str | None = None,
    target_id: str | uuid.UUID | None = None,
    details: dict[str, Any] | None = None,
) -> AuditEvent:
    # 1. Bump the head row first. This acquires the row lock (Postgres) / the
    #    database write lock (SQLite) and holds it until commit, serialising all
    #    concurrent appenders so the chain can never fork.
    await session.execute(
        update(AuditChainHead).where(AuditChainHead.id == 1).values(seq=AuditChainHead.seq + 1)
    )
    row = (
        await session.execute(
            select(AuditChainHead.seq, AuditChainHead.last_hash).where(AuditChainHead.id == 1)
        )
    ).one()
    seq, prev_hash = int(row.seq), str(row.last_hash)

    ev = AuditEvent(
        seq=seq,
        ts=utcnow(),
        actor_type=ctx.actor_type,
        actor_id=ctx.actor_id,
        org_id=org_id,
        action=action,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        ip=ctx.ip,
        user_agent=ctx.user_agent,
        request_id=ctx.request_id,
        details=details or {},
        prev_hash=prev_hash,
        hash="",
    )
    ev.hash = event_hash(ev)
    session.add(ev)
    await session.execute(
        update(AuditChainHead).where(AuditChainHead.id == 1).values(last_hash=ev.hash)
    )
    await session.flush()
    return ev


@dataclass(frozen=True, slots=True)
class ChainVerification:
    ok: bool
    checked: int
    first_bad_seq: int | None = None
    reason: str | None = None


async def _iter_events(session: AsyncSession, batch: int = 500) -> AsyncIterator[AuditEvent]:
    last = 0
    while True:
        rows = (
            (
                await session.execute(
                    select(AuditEvent)
                    .where(AuditEvent.seq > last)
                    .order_by(AuditEvent.seq)
                    .limit(batch)
                )
            )
            .scalars()
            .all()
        )
        if not rows:
            return
        for ev in rows:
            yield ev
        last = rows[-1].seq


async def verify_chain(session: AsyncSession) -> ChainVerification:
    prev = GENESIS_HASH
    expected_seq = 1
    checked = 0
    async for ev in _iter_events(session):
        if ev.seq != expected_seq:
            return ChainVerification(False, checked, expected_seq, "missing or reordered event")
        if ev.prev_hash != prev:
            return ChainVerification(False, checked, ev.seq, "prev_hash does not link")
        if event_hash(ev) != ev.hash:
            return ChainVerification(False, checked, ev.seq, "event contents modified")
        prev = ev.hash
        expected_seq += 1
        checked += 1
    head = (
        await session.execute(select(AuditChainHead).where(AuditChainHead.id == 1))
    ).scalar_one()
    if head.seq != checked or head.last_hash != prev:
        return ChainVerification(False, checked, checked + 1, "chain head mismatch (truncation)")
    return ChainVerification(True, checked)
