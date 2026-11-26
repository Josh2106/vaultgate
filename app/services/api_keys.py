"""Machine credentials scoped to one organisation.

Format: ``vg_live_<12 hex prefix>_<43 char secret>`` (``vg_test_`` outside
production, so a test key can never authenticate against prod). The prefix is
stored in clear for O(1) lookup and for display ("which key is this?"); the
full key is stored only as SHA-256 and compared in constant time.
"""

from __future__ import annotations

import secrets
import uuid
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import InvalidToken, NotFound, PermissionDenied, ValidationFailed
from app.core.permissions import API_KEY_GRANTABLE, Permission
from app.core.security import constant_time_equals, generate_token, sha256_hex
from app.db.base import utcnow
from app.db.models import ApiKey, Organization
from app.services import audit
from app.services.context import OrgAccess
from app.services.pagination import Page, paginate_by_time
from app.state import AppState

PREFIX_HEX_LEN = 12
LAST_USED_RESOLUTION = timedelta(seconds=60)
KNOWN_ENV_PREFIXES = ("vg_live_", "vg_test_")


def looks_like_api_key(raw: str) -> bool:
    return raw.startswith(KNOWN_ENV_PREFIXES)


def parse_key(raw: str, env_prefix: str) -> str | None:
    """Return the lookup prefix if ``raw`` is well-formed for this environment."""
    if not raw.startswith(env_prefix):
        return None
    rest = raw[len(env_prefix) :]
    if len(rest) < PREFIX_HEX_LEN + 2 or rest[PREFIX_HEX_LEN] != "_":
        return None
    prefix = rest[:PREFIX_HEX_LEN]
    if any(c not in "0123456789abcdef" for c in prefix):
        return None
    return prefix


async def create(
    state: AppState,
    session: AsyncSession,
    access: OrgAccess,
    *,
    name: str,
    scopes: list[Permission],
    expires_in_days: int | None,
) -> tuple[ApiKey, str]:
    requested = frozenset(scopes)
    not_grantable = requested - API_KEY_GRANTABLE
    if not_grantable:
        raise ValidationFailed(
            f"Scopes cannot be granted to API keys: {', '.join(sorted(not_grantable))}"
        )
    escalation = requested - access.permissions
    if escalation:  # pragma: no cover - only admins+ can mint keys, and they hold all grantables
        raise PermissionDenied(
            f"You cannot grant permissions you do not hold: {', '.join(sorted(escalation))}"
        )
    prefix = secrets.token_hex(PREFIX_HEX_LEN // 2)
    raw = f"{state.settings.api_key_prefix}{prefix}_{generate_token()}"
    key = ApiKey(
        org_id=access.org_id,
        name=name,
        prefix=prefix,
        key_hash=sha256_hex(raw),
        scopes=sorted(s.value for s in requested),
        created_by_id=access.principal.user.id if access.principal.user else None,
        expires_at=utcnow() + timedelta(days=expires_in_days) if expires_in_days else None,
    )
    session.add(key)
    await session.flush()
    await audit.record(
        session,
        access.ctx,
        "api_key.created",
        org_id=access.org_id,
        target_type="api_key",
        target_id=key.id,
        details={"name": name, "scopes": key.scopes, "prefix": prefix},
    )
    await session.commit()
    return key, raw


async def list_keys(
    session: AsyncSession, access: OrgAccess, *, limit: int | None, cursor: str | None
) -> Page[ApiKey]:
    stmt = select(ApiKey).where(ApiKey.org_id == access.org_id)
    return await paginate_by_time(
        session, stmt, ApiKey.created_at, ApiKey.id, limit=limit, cursor=cursor
    )


async def revoke(session: AsyncSession, access: OrgAccess, key_id: uuid.UUID) -> None:
    key = await session.get(ApiKey, key_id)
    if key is None or key.org_id != access.org_id:
        raise NotFound("API key not found.")
    if key.revoked_at is None:
        key.revoked_at = utcnow()
        await audit.record(
            session,
            access.ctx,
            "api_key.revoked",
            org_id=access.org_id,
            target_type="api_key",
            target_id=key.id,
        )
        await session.commit()


async def authenticate(state: AppState, session: AsyncSession, raw: str) -> ApiKey:
    prefix = parse_key(raw, state.settings.api_key_prefix)
    if prefix is None:
        raise InvalidToken("Malformed API key.")
    key = (
        await session.execute(select(ApiKey).where(ApiKey.prefix == prefix))
    ).scalar_one_or_none()
    # Compare even when not found so timing does not reveal valid prefixes.
    expected = key.key_hash if key is not None else sha256_hex(b"\0")
    if not constant_time_equals(expected, sha256_hex(raw)) or key is None:
        raise InvalidToken("Invalid API key.")
    now = utcnow()
    if key.revoked_at is not None or (key.expires_at is not None and key.expires_at <= now):
        raise InvalidToken("API key revoked or expired.")
    org = await session.get(Organization, key.org_id)
    if org is None or org.deleted_at is not None:
        raise InvalidToken("Invalid API key.")
    # Throttle last_used writes to at most one per minute per key.
    if key.last_used_at is None or now - key.last_used_at > LAST_USED_RESOLUTION:
        key.last_used_at = now
        await session.commit()
    return key
