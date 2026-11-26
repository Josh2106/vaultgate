from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Path, Query, Response, status

from app.api.deps import SessionDep, StateDep, require
from app.core.permissions import Permission
from app.schemas.common import Page
from app.schemas.secrets import (
    SecretCreate,
    SecretMeta,
    SecretUpdate,
    SecretVersionOut,
    SecretWithValue,
)
from app.services import secrets
from app.services.context import OrgAccess

router = APIRouter(prefix="/orgs/{org_id}/projects/{project_id}/secrets", tags=["secrets"])

Limit = Annotated[int | None, Query(ge=1, le=100)]
Cursor = Annotated[str | None, Query(max_length=512)]
SecretNamePath = Annotated[
    str, Path(min_length=1, max_length=128, pattern=r"^[A-Za-z_][A-Za-z0-9_.\-]*$")
]


@router.post("", status_code=status.HTTP_201_CREATED, response_model=SecretMeta)
async def create_secret(
    project_id: uuid.UUID,
    body: SecretCreate,
    state: StateDep,
    session: SessionDep,
    access: Annotated[OrgAccess, Depends(require(Permission.SECRET_WRITE))],
) -> SecretMeta:
    secret = await secrets.create_secret(
        state, session, access, project_id, name=body.name, value=body.value
    )
    return SecretMeta.model_validate(secret)


@router.get("", response_model=Page[SecretMeta])
async def list_secrets(
    project_id: uuid.UUID,
    session: SessionDep,
    access: Annotated[OrgAccess, Depends(require(Permission.SECRET_LIST))],
    limit: Limit = None,
    cursor: Cursor = None,
    include_deleted: bool = False,
) -> Page[SecretMeta]:
    page = await secrets.list_secrets(
        session, access, project_id, limit=limit, cursor=cursor, include_deleted=include_deleted
    )
    return Page[SecretMeta](
        items=[SecretMeta.model_validate(s) for s in page.items], next_cursor=page.next_cursor
    )


@router.get("/{name}", response_model=SecretWithValue)
async def read_secret(
    project_id: uuid.UUID,
    name: SecretNamePath,
    state: StateDep,
    session: SessionDep,
    access: Annotated[OrgAccess, Depends(require(Permission.SECRET_READ))],
    version: Annotated[int | None, Query(ge=1)] = None,
) -> SecretWithValue:
    d = await secrets.read_secret(state, session, access, project_id, name, version=version)
    return SecretWithValue(
        id=d.secret.id,
        name=d.secret.name,
        current_version=d.secret.current_version,
        created_at=d.secret.created_at,
        updated_at=d.secret.updated_at,
        version=d.version,
        value=d.value,
    )


@router.put("/{name}", response_model=SecretMeta)
async def update_secret(
    project_id: uuid.UUID,
    name: SecretNamePath,
    body: SecretUpdate,
    state: StateDep,
    session: SessionDep,
    access: Annotated[OrgAccess, Depends(require(Permission.SECRET_WRITE))],
) -> SecretMeta:
    secret = await secrets.update_secret(state, session, access, project_id, name, value=body.value)
    return SecretMeta.model_validate(secret)


@router.get("/{name}/versions", response_model=list[SecretVersionOut])
async def list_versions(
    project_id: uuid.UUID,
    name: SecretNamePath,
    session: SessionDep,
    access: Annotated[OrgAccess, Depends(require(Permission.SECRET_LIST))],
) -> list[SecretVersionOut]:
    rows = await secrets.list_versions(session, access, project_id, name)
    return [SecretVersionOut.model_validate(r) for r in rows]


@router.delete("/{name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_secret(
    project_id: uuid.UUID,
    name: SecretNamePath,
    session: SessionDep,
    access: Annotated[OrgAccess, Depends(require(Permission.SECRET_DELETE))],
) -> Response:
    await secrets.delete_secret(session, access, project_id, name)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{name}/restore", response_model=SecretMeta)
async def restore_secret(
    project_id: uuid.UUID,
    name: SecretNamePath,
    session: SessionDep,
    access: Annotated[OrgAccess, Depends(require(Permission.SECRET_DELETE))],
) -> SecretMeta:
    return SecretMeta.model_validate(
        await secrets.restore_secret(session, access, project_id, name)
    )
