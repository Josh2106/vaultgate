from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, StringConstraints


class Schema(BaseModel):
    """Base for request bodies: reject unknown fields (mass-assignment protection).

    Whitespace is *not* stripped globally - secret values and passwords must be
    stored byte-for-byte. Identifier-like fields opt in via ``StringConstraints``.
    """

    model_config = ConfigDict(extra="forbid")


class OutSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Page[T](BaseModel):
    items: list[T]
    next_cursor: str | None = Field(
        default=None, description="Opaque cursor for the next page; null when exhausted."
    )


Slug = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=2,
        max_length=64,
        pattern=r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$",
    ),
]
Name = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=200)]


class Message(OutSchema):
    detail: str
