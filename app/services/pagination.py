"""Keyset (cursor) pagination.

Offset pagination is O(offset) for the database and returns duplicated or
skipped rows when data changes between pages. Keyset pagination seeks directly
to ``(created_at, id) < (cursor.created_at, cursor.id)`` using the index, so it
is O(page size) and stable under concurrent inserts. See ``docs/adr/0003``.
"""

from __future__ import annotations

import base64
import binascii
import json
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from sqlalchemy import Select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import InstrumentedAttribute

from app.core.errors import ValidationFailed

MAX_LIMIT = 100
DEFAULT_LIMIT = 50


class _Keyed(Protocol):
    id: Any
    created_at: datetime


@dataclass(slots=True)
class Page[T]:
    items: list[T]
    next_cursor: str | None


def _b64e(doc: dict[str, Any]) -> str:
    raw = json.dumps(doc, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64d(cursor: str) -> dict[str, Any]:
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        doc = json.loads(base64.urlsafe_b64decode(padded.encode()))
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise ValidationFailed("Malformed pagination cursor.") from exc
    if not isinstance(doc, dict):
        raise ValidationFailed("Malformed pagination cursor.")
    return doc


def encode_time_cursor(created_at: datetime, row_id: uuid.UUID) -> str:
    return _b64e({"t": created_at.isoformat(), "i": str(row_id)})


def decode_time_cursor(cursor: str) -> tuple[datetime, uuid.UUID]:
    doc = _b64d(cursor)
    try:
        return datetime.fromisoformat(str(doc["t"])), uuid.UUID(str(doc["i"]))
    except (KeyError, ValueError) as exc:
        raise ValidationFailed("Malformed pagination cursor.") from exc


def encode_seq_cursor(seq: int) -> str:
    return _b64e({"s": seq})


def decode_seq_cursor(cursor: str) -> int:
    doc = _b64d(cursor)
    value = doc.get("s")
    if not isinstance(value, int) or value < 0:
        raise ValidationFailed("Malformed pagination cursor.")
    return value


def clamp_limit(limit: int | None) -> int:
    if limit is None:
        return DEFAULT_LIMIT
    return max(1, min(MAX_LIMIT, limit))


async def paginate_by_time[M: _Keyed](
    session: AsyncSession,
    stmt: Select[M],
    created_col: InstrumentedAttribute[datetime],
    id_col: InstrumentedAttribute[uuid.UUID],
    *,
    limit: int | None,
    cursor: str | None,
) -> Page[M]:
    """Newest-first keyset pagination over ``(created_at, id)``."""
    size = clamp_limit(limit)
    if cursor:
        ts, rid = decode_time_cursor(cursor)
        stmt = stmt.where(or_(created_col < ts, and_(created_col == ts, id_col < rid)))
    stmt = stmt.order_by(created_col.desc(), id_col.desc()).limit(size + 1)
    rows = list((await session.execute(stmt)).scalars().all())
    if len(rows) <= size:
        return Page(rows, None)
    rows = rows[:size]
    last = rows[-1]
    return Page(rows, encode_time_cursor(last.created_at, last.id))
