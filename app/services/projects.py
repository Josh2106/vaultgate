"""Projects group secrets inside an organisation."""

from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import Conflict, NotFound
from app.db.base import utcnow
from app.db.models import Project
from app.services import audit
from app.services.context import OrgAccess
from app.services.pagination import Page, paginate_by_time


async def get_project(session: AsyncSession, org_id: uuid.UUID, project_id: uuid.UUID) -> Project:
    """Tenant-scoped lookup: a project id from another org is indistinguishable from 404."""
    project = await session.get(Project, project_id)
    if project is None or project.org_id != org_id or project.deleted_at is not None:
        raise NotFound("Project not found.")
    return project


async def create_project(
    session: AsyncSession, access: OrgAccess, *, name: str, slug: str, description: str
) -> Project:
    project = Project(org_id=access.org_id, name=name, slug=slug, description=description)
    session.add(project)
    try:
        await session.flush()
    except IntegrityError as exc:
        await session.rollback()
        raise Conflict(f"Project slug {slug!r} already exists in this organisation.") from exc
    await audit.record(
        session,
        access.ctx,
        "project.created",
        org_id=access.org_id,
        target_type="project",
        target_id=project.id,
        details={"slug": slug},
    )
    await session.commit()
    return project


async def list_projects(
    session: AsyncSession, access: OrgAccess, *, limit: int | None, cursor: str | None
) -> Page[Project]:
    stmt = select(Project).where(Project.org_id == access.org_id, Project.deleted_at.is_(None))
    return await paginate_by_time(
        session, stmt, Project.created_at, Project.id, limit=limit, cursor=cursor
    )


async def update_project(
    session: AsyncSession,
    access: OrgAccess,
    project_id: uuid.UUID,
    *,
    name: str | None,
    description: str | None,
) -> Project:
    project = await get_project(session, access.org_id, project_id)
    changes: dict[str, object] = {}
    if name is not None and name != project.name:
        changes["name"] = {"from": project.name, "to": name}
        project.name = name
    if description is not None and description != project.description:
        changes["description"] = True
        project.description = description
    if changes:
        project.updated_at = utcnow()
        await audit.record(
            session,
            access.ctx,
            "project.updated",
            org_id=access.org_id,
            target_type="project",
            target_id=project.id,
            details=changes,
        )
        await session.commit()
    return project


async def delete_project(session: AsyncSession, access: OrgAccess, project_id: uuid.UUID) -> None:
    project = await get_project(session, access.org_id, project_id)
    project.deleted_at = utcnow()
    await audit.record(
        session,
        access.ctx,
        "project.deleted",
        org_id=access.org_id,
        target_type="project",
        target_id=project.id,
    )
    await session.commit()
