from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response, status

from app.api.deps import CurrentUser, SessionDep, StateDep, UserCtx, require
from app.core.permissions import Permission, Role
from app.schemas.common import Page
from app.schemas.orgs import (
    MemberAdd,
    MemberOut,
    MemberUpdate,
    OrgCreate,
    OrgOut,
    OrgUpdate,
    OrgWithRole,
)
from app.services import orgs
from app.services.context import OrgAccess
from app.services.orgs import MemberView

router = APIRouter(prefix="/orgs", tags=["organisations"])

Limit = Annotated[int | None, Query(ge=1, le=100)]
Cursor = Annotated[str | None, Query(max_length=512)]


def _member_out(v: MemberView) -> MemberOut:
    return MemberOut(
        user_id=v.user.id,
        email=v.user.email,
        full_name=v.user.full_name,
        role=Role(v.membership.role),
        joined_at=v.membership.created_at,
    )


@router.post("", status_code=status.HTTP_201_CREATED, response_model=OrgOut)
async def create_org(
    body: OrgCreate, state: StateDep, session: SessionDep, ctx: UserCtx, user: CurrentUser
) -> OrgOut:
    org = await orgs.create_org(state, session, ctx, user, name=body.name, slug=body.slug)
    return OrgOut.model_validate(org)


@router.get("", response_model=Page[OrgWithRole])
async def list_orgs(
    session: SessionDep, user: CurrentUser, limit: Limit = None, cursor: Cursor = None
) -> Page[OrgWithRole]:
    page, roles = await orgs.list_for_user(session, user, limit=limit, cursor=cursor)
    items = [
        OrgWithRole(id=o.id, name=o.name, slug=o.slug, created_at=o.created_at, role=roles[o.id])
        for o in page.items
    ]
    return Page[OrgWithRole](items=items, next_cursor=page.next_cursor)


@router.get("/{org_id}", response_model=OrgOut)
async def get_org(
    session: SessionDep, access: Annotated[OrgAccess, Depends(require(Permission.ORG_READ))]
) -> OrgOut:
    return OrgOut.model_validate(await orgs.get_org(session, access.org_id))


@router.patch("/{org_id}", response_model=OrgOut)
async def update_org(
    body: OrgUpdate,
    session: SessionDep,
    access: Annotated[OrgAccess, Depends(require(Permission.ORG_UPDATE))],
) -> OrgOut:
    return OrgOut.model_validate(await orgs.update_org(session, access, name=body.name))


@router.delete("/{org_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_org(
    session: SessionDep, access: Annotated[OrgAccess, Depends(require(Permission.ORG_DELETE))]
) -> Response:
    await orgs.delete_org(session, access)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{org_id}/members", response_model=Page[MemberOut])
async def list_members(
    session: SessionDep,
    access: Annotated[OrgAccess, Depends(require(Permission.MEMBER_READ))],
    limit: Limit = None,
    cursor: Cursor = None,
) -> Page[MemberOut]:
    page = await orgs.list_members(session, access, limit=limit, cursor=cursor)
    return Page[MemberOut](items=[_member_out(v) for v in page.items], next_cursor=page.next_cursor)


@router.post("/{org_id}/members", status_code=status.HTTP_201_CREATED, response_model=MemberOut)
async def add_member(
    body: MemberAdd,
    session: SessionDep,
    access: Annotated[OrgAccess, Depends(require(Permission.MEMBER_MANAGE))],
) -> MemberOut:
    return _member_out(
        await orgs.add_member(session, access, email=str(body.email), role=body.role)
    )


@router.patch("/{org_id}/members/{user_id}", response_model=MemberOut)
async def change_member_role(
    user_id: uuid.UUID,
    body: MemberUpdate,
    session: SessionDep,
    access: Annotated[OrgAccess, Depends(require(Permission.MEMBER_MANAGE))],
) -> MemberOut:
    return _member_out(await orgs.change_role(session, access, user_id=user_id, role=body.role))


@router.delete("/{org_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_member(
    user_id: uuid.UUID,
    session: SessionDep,
    access: Annotated[OrgAccess, Depends(require(Permission.MEMBER_MANAGE))],
) -> Response:
    await orgs.remove_member(session, access, user_id=user_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
