from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated

from pydantic import Field, StringConstraints

from app.schemas.common import OutSchema, Schema

MAX_SECRET_BYTES = 64 * 1024

SecretName = Annotated[
    str,
    StringConstraints(min_length=1, max_length=128, pattern=r"^[A-Za-z_][A-Za-z0-9_.\-]*$"),
]
SecretValue = Annotated[str, Field(min_length=1, max_length=MAX_SECRET_BYTES)]


class SecretCreate(Schema):
    name: SecretName
    value: SecretValue


class SecretUpdate(Schema):
    value: SecretValue


class SecretMeta(OutSchema):
    id: uuid.UUID
    name: str
    current_version: int
    created_at: datetime
    updated_at: datetime
    deleted_at: datetime | None = None


class SecretWithValue(SecretMeta):
    version: int
    value: str


class SecretVersionOut(OutSchema):
    version: int
    master_key_id: str
    created_by_type: str
    created_by_id: str
    created_at: datetime
