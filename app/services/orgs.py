"""Organisations and memberships."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import Conflict, EmailNotVerified, NotFound, PermissionDenied, ValidationFailed
from app.core.permissions import Role
from app.db.base import utcnow
from app.db.models import Membership, Organization, User
from app.services import audit
from app.services.context import OrgAccess, RequestContext
from app.services.pagination import Page, paginate_by_time
from app.state import AppState


@dataclass(slots=True)
class MemberView:
    membership: Membership
    user: User


async def create_org(
    state: AppState,
    session: AsyncSession,
    ctx: RequestContext,
    user: User,
    *,
    name: str,
    slug: str,
) -> Organization:
    if state.settings.require_verified_email and user.email_verified_at is None:
        raise EmailNotVerified()
    org = Organization(name=name, slug=slug)
    session.add(org)
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        raise Conflict(f"Organisation slug {slug!r} is taken.") from exc
    session.add(Membership(org_id=org.id, user_id=user.id, role=Role.OWNER.value))
    await audit.record(
        session,
        ctx,
        "org.created",
        org_id=org.id,
        target_type="org",
        target_id=org.id,
        details={"slug": slug},
    )
    await session.commit()
    return org


async def list_for_user(
    session: AsyncSession, user: User, *, limit: int | None, cursor: str | None
) -> tuple[Page[Organization], dict[uuid.UUID, Role]]:
    stmt = (
        select(Organization)
        .join(Membership, Membership.org_id == Organization.id)
        .where(Membership.user_id == user.id, Organization.deleted_at.is_(None))
    )
    page = await paginate_by_time(
        session, stmt, Organization.created_at, Organization.id, limit=limit, cursor=cursor
    )
    ids = [o.id for o in page.items]
    roles: dict[uuid.UUID, Role] = {}
    if ids:
        rows = await session.execute(
            select(Membership.org_id, Membership.role).where(
                Membership.user_id == user.id, Membership.org_id.in_(ids)
            )
        )
        roles = {r.org_id: Role(r.role) for r in rows}
    return page, roles


async def get_org(session: AsyncSession, org_id: uuid.UUID) -> Organization:
    org = await session.get(Organization, org_id)
    if org is None or org.deleted_at is not None:
        raise NotFound("Organisation not found.")
    return org


async def update_org(session: AsyncSession, access: OrgAccess, *, name: str) -> Organization:
    org = await get_org(session, access.org_id)
    old = org.name
    org.name = name
    await audit.record(
        session,
        access.ctx,
        "org.updated",
        org_id=org.id,
        target_type="org",
        target_id=org.id,
        details={"name": {"from": old, "to": name}},
    )
    await session.commit()
    return org


async def delete_org(session: AsyncSession, access: OrgAccess) -> None:
    org = await get_org(session, access.org_id)
    org.deleted_at = utcnow()
    await audit.record(
        session, access.ctx, "org.deleted", org_id=org.id, target_type="org", target_id=org.id
    )
    await session.commit()


# --------------------------------------------------------------------------- members


async def list_members(
    session: AsyncSession, access: OrgAccess, *, limit: int | None, cursor: str | None
) -> Page[MemberView]:
    stmt = select(Membership).where(Membership.org_id == access.org_id)
    page = await paginate_by_time(
        session, stmt, Membership.created_at, Membership.id, limit=limit, cursor=cursor
    )
    users: dict[uuid.UUID, User] = {}
    if page.items:
        result = await session.execute(
            select(User).where(User.id.in_([m.user_id for m in page.items]))
        )
        users = {u.id: u for u in result.scalars()}
    return Page([MemberView(m, users[m.user_id]) for m in page.items], page.next_cursor)


def _assert_can_assign(access: OrgAccess, target_role: Role, current_role: Role | None) -> None:
    """Admins manage members and admins; only owners touch the owner role."""
    actor = access.role
    if actor is None:  # pragma: no cover - API keys cannot hold member:manage
        raise PermissionDenied()
    if actor is Role.OWNER:
        return
    if target_role is Role.OWNER or current_role is Role.OWNER:
        raise PermissionDenied("Only owners can grant, change or remove the owner role.")


async def _owner_count(session: AsyncSession, org_id: uuid.UUID) -> int:
    return int(
        (
            await session.execute(
                select(func.count())
                .select_from(Membership)
                .where(Membership.org_id == org_id, Membership.role == Role.OWNER.value)
            )
        ).scalar_one()
    )


async def _get_membership(
    session: AsyncSession, org_id: uuid.UUID, user_id: uuid.UUID
) -> Membership:
    m = (
        await session.execute(
            select(Membership).where(Membership.org_id == org_id, Membership.user_id == user_id)
        )
    ).scalar_one_or_none()
    if m is None:
        raise NotFound("Member not found.")
    return m


async def add_member(
    session: AsyncSession, access: OrgAccess, *, email: str, role: Role
) -> MemberView:
    _assert_can_assign(access, role, None)
    user = (
        await session.execute(select(User).where(User.email == email.strip().lower()))
    ).scalar_one_or_none()
    if user is None or not user.is_active:
        raise NotFound("No active user with that email address.")
    existing = (
        await session.execute(
            select(Membership).where(
                Membership.org_id == access.org_id, Membership.user_id == user.id
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise Conflict("User is already a member.")
    m = Membership(org_id=access.org_id, user_id=user.id, role=role.value)
    session.add(m)
    await session.flush()
    await audit.record(
        session,
        access.ctx,
        "member.added",
        org_id=access.org_id,
        target_type="user",
        target_id=user.id,
        details={"role": role.value},
    )
    await session.commit()
    return MemberView(m, user)


async def change_role(
    session: AsyncSession, access: OrgAccess, *, user_id: uuid.UUID, role: Role
) -> MemberView:
    m = await _get_membership(session, access.org_id, user_id)
    current = Role(m.role)
    _assert_can_assign(access, role, current)
    if (
        current is Role.OWNER
        and role is not Role.OWNER
        and await _owner_count(session, access.org_id) <= 1
    ):
        raise ValidationFailed("An organisation must keep at least one owner.")
    m.role = role.value
    await audit.record(
        session,
        access.ctx,
        "member.role_changed",
        org_id=access.org_id,
        target_type="user",
        target_id=user_id,
        details={"from": current.value, "to": role.value},
    )
    await session.commit()
    user = await session.get(User, user_id)
    assert user is not None  # noqa: S101
    return MemberView(m, user)


async def remove_member(session: AsyncSession, access: OrgAccess, *, user_id: uuid.UUID) -> None:
    m = await _get_membership(session, access.org_id, user_id)
    current = Role(m.role)
    _assert_can_assign(access, current, current)
    if current is Role.OWNER and await _owner_count(session, access.org_id) <= 1:
        raise ValidationFailed("An organisation must keep at least one owner.")
    await session.delete(m)
    await audit.record(
        session,
        access.ctx,
        "member.removed",
        org_id=access.org_id,
        target_type="user",
        target_id=user_id,
        details={"role": current.value},
    )
    await session.commit()
