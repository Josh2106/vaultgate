from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response, status

from app.api.deps import SessionDep, StateDep, require
from app.core.permissions import Permission
from app.schemas.common import Page
from app.schemas.orgs import ApiKeyCreate, ApiKeyCreated, ApiKeyOut
from app.services import api_keys
from app.services.context import OrgAccess

router = APIRouter(prefix="/orgs/{org_id}/api-keys", tags=["api-keys"])


@router.post("", status_code=status.HTTP_201_CREATED, response_model=ApiKeyCreated)
async def create_api_key(
    body: ApiKeyCreate,
    state: StateDep,
    session: SessionDep,
    access: Annotated[OrgAccess, Depends(require(Permission.APIKEY_MANAGE))],
) -> ApiKeyCreated:
    key, raw = await api_keys.create(
        state,
        session,
        access,
        name=body.name,
        scopes=body.scopes,
        expires_in_days=body.expires_in_days,
    )
    return ApiKeyCreated(**ApiKeyOut.model_validate(key).model_dump(), key=raw)


@router.get("", response_model=Page[ApiKeyOut])
async def list_api_keys(
    session: SessionDep,
    access: Annotated[OrgAccess, Depends(require(Permission.APIKEY_READ))],
    limit: Annotated[int | None, Query(ge=1, le=100)] = None,
    cursor: Annotated[str | None, Query(max_length=512)] = None,
) -> Page[ApiKeyOut]:
    page = await api_keys.list_keys(session, access, limit=limit, cursor=cursor)
    return Page[ApiKeyOut](
        items=[ApiKeyOut.model_validate(k) for k in page.items], next_cursor=page.next_cursor
    )


@router.delete("/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(
    key_id: uuid.UUID,
    session: SessionDep,
    access: Annotated[OrgAccess, Depends(require(Permission.APIKEY_MANAGE))],
) -> Response:
    await api_keys.revoke(session, access, key_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
