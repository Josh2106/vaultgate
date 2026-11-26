from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select

from app.api.deps import SessionDep, require
from app.core.permissions import Permission
from app.db.models import AuditEvent
from app.schemas.common import Page
from app.schemas.orgs import AuditEventOut
from app.services.context import OrgAccess
from app.services.pagination import clamp_limit, decode_seq_cursor, encode_seq_cursor

router = APIRouter(prefix="/orgs/{org_id}/audit-events", tags=["audit"])


@router.get("", response_model=Page[AuditEventOut])
async def list_audit_events(
    session: SessionDep,
    access: Annotated[OrgAccess, Depends(require(Permission.AUDIT_READ))],
    action: Annotated[str | None, Query(max_length=64, pattern=r"^[a-z_.]+$")] = None,
    limit: Annotated[int | None, Query(ge=1, le=100)] = None,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
) -> Page[AuditEventOut]:
    """Newest-first audit events for this organisation."""
    size = clamp_limit(limit)
    stmt = select(AuditEvent).where(AuditEvent.org_id == access.org_id)
    if action:
        stmt = stmt.where(AuditEvent.action == action)
    if cursor:
        stmt = stmt.where(AuditEvent.seq < decode_seq_cursor(cursor))
    rows = list(
        (await session.execute(stmt.order_by(AuditEvent.seq.desc()).limit(size + 1))).scalars()
    )
    next_cursor = encode_seq_cursor(rows[size - 1].seq) if len(rows) > size else None
    return Page[AuditEventOut](
        items=[AuditEventOut.model_validate(r) for r in rows[:size]], next_cursor=next_cursor
    )
