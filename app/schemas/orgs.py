from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from pydantic import EmailStr, Field, StringConstraints

from app.core.permissions import Permission, Role
from app.schemas.common import Name, OutSchema, Schema, Slug


class OrgCreate(Schema):
    name: Name
    slug: Slug


class OrgUpdate(Schema):
    name: Name


class OrgOut(OutSchema):
    id: uuid.UUID
    name: str
    slug: str
    created_at: datetime


class OrgWithRole(OrgOut):
    role: Role


class MemberAdd(Schema):
    email: EmailStr
    role: Role = Role.MEMBER


class MemberUpdate(Schema):
    role: Role


class MemberOut(OutSchema):
    user_id: uuid.UUID
    email: str
    full_name: str
    role: Role
    joined_at: datetime


class ProjectCreate(Schema):
    name: Name
    slug: Slug
    description: Annotated[str, StringConstraints(max_length=2000)] = ""


class ProjectUpdate(Schema):
    name: Name | None = None
    description: Annotated[str, StringConstraints(max_length=2000)] | None = None


class ProjectOut(OutSchema):
    id: uuid.UUID
    org_id: uuid.UUID
    name: str
    slug: str
    description: str
    created_at: datetime
    updated_at: datetime


class ApiKeyCreate(Schema):
    name: Name
    scopes: list[Permission] = Field(min_length=1)
    expires_in_days: int | None = Field(default=90, ge=1, le=365)


class ApiKeyOut(OutSchema):
    id: uuid.UUID
    name: str
    prefix: str
    scopes: list[str]
    created_at: datetime
    expires_at: datetime | None
    last_used_at: datetime | None
    revoked_at: datetime | None


class ApiKeyCreated(ApiKeyOut):
    key: str = Field(description="The full API key. Shown exactly once - it is stored hashed.")


class AuditEventOut(OutSchema):
    seq: int
    ts: datetime
    actor_type: str
    actor_id: str | None
    action: str
    target_type: str | None
    target_id: str | None
    ip: str | None
    user_agent: str | None
    request_id: str | None
    details: dict[str, object]
    hash: str
