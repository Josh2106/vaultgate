"""Who is acting and from where - threaded through services for auditing."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import StrEnum

from app.core.permissions import Permission, Role
from app.db.models import ApiKey, User


class ActorType(StrEnum):
    USER = "user"
    API_KEY = "api_key"
    ANONYMOUS = "anonymous"
    SYSTEM = "system"


@dataclass(frozen=True, slots=True)
class RequestContext:
    actor_type: str = ActorType.ANONYMOUS
    actor_id: str | None = None
    ip: str | None = None
    user_agent: str | None = None
    request_id: str | None = None

    def as_actor(self, actor_type: ActorType, actor_id: str | uuid.UUID) -> RequestContext:
        return RequestContext(
            actor_type=actor_type,
            actor_id=str(actor_id),
            ip=self.ip,
            user_agent=self.user_agent,
            request_id=self.request_id,
        )


@dataclass(slots=True)
class Principal:
    """An authenticated caller: either a human user (JWT) or an API key."""

    user: User | None = None
    api_key: ApiKey | None = None
    amr: list[str] = field(default_factory=list)

    @property
    def actor_type(self) -> ActorType:
        return ActorType.USER if self.user is not None else ActorType.API_KEY

    @property
    def actor_id(self) -> str:
        if self.user is not None:
            return str(self.user.id)
        assert self.api_key is not None  # noqa: S101
        return str(self.api_key.id)


@dataclass(slots=True)
class OrgAccess:
    """Result of an authorisation check against one organisation."""

    principal: Principal
    org_id: uuid.UUID
    role: Role | None  # None for API keys (they carry scopes, not roles)
    permissions: frozenset[Permission]
    ctx: RequestContext
