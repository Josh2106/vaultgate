from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Query, Response, status

from app.api.deps import SessionDep, require
from app.core.permissions import Permission
from app.schemas.common import Page
from app.schemas.orgs import ProjectCreate, ProjectOut, ProjectUpdate
from app.services import projects
from app.services.context import OrgAccess

router = APIRouter(prefix="/orgs/{org_id}/projects", tags=["projects"])

Limit = Annotated[int | None, Query(ge=1, le=100)]
Cursor = Annotated[str | None, Query(max_length=512)]


@router.post("", status_code=status.HTTP_201_CREATED, response_model=ProjectOut)
async def create_project(
    body: ProjectCreate,
    session: SessionDep,
    access: Annotated[OrgAccess, Depends(require(Permission.PROJECT_WRITE))],
) -> ProjectOut:
    project = await projects.create_project(
        session, access, name=body.name, slug=body.slug, description=body.description
    )
    return ProjectOut.model_validate(project)


@router.get("", response_model=Page[ProjectOut])
async def list_projects(
    session: SessionDep,
    access: Annotated[OrgAccess, Depends(require(Permission.PROJECT_READ))],
    limit: Limit = None,
    cursor: Cursor = None,
) -> Page[ProjectOut]:
    page = await projects.list_projects(session, access, limit=limit, cursor=cursor)
    return Page[ProjectOut](
        items=[ProjectOut.model_validate(p) for p in page.items], next_cursor=page.next_cursor
    )


@router.get("/{project_id}", response_model=ProjectOut)
async def get_project(
    project_id: uuid.UUID,
    session: SessionDep,
    access: Annotated[OrgAccess, Depends(require(Permission.PROJECT_READ))],
) -> ProjectOut:
    return ProjectOut.model_validate(await projects.get_project(session, access.org_id, project_id))


@router.patch("/{project_id}", response_model=ProjectOut)
async def update_project(
    project_id: uuid.UUID,
    body: ProjectUpdate,
    session: SessionDep,
    access: Annotated[OrgAccess, Depends(require(Permission.PROJECT_WRITE))],
) -> ProjectOut:
    project = await projects.update_project(
        session, access, project_id, name=body.name, description=body.description
    )
    return ProjectOut.model_validate(project)


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_project(
    project_id: uuid.UUID,
    session: SessionDep,
    access: Annotated[OrgAccess, Depends(require(Permission.PROJECT_DELETE))],
) -> Response:
    await projects.delete_project(session, access, project_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
