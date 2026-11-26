"""FastAPI dependencies: state, DB session, authentication and authorisation."""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from typing import Annotated

from fastapi import Depends, Path, Request, Security
from fastapi.security import APIKeyHeader, OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.context import request_id_ctx
from app.core.errors import InvalidToken, NotAuthenticated, NotFound, PermissionDenied
from app.core.net import client_ip
from app.core.permissions import API_KEY_GRANTABLE, ROLE_PERMISSIONS, Permission, Role
from app.core.tokens import TokenType
from app.db.models import Membership, Organization, User
from app.services import api_keys
from app.services.context import ActorType, OrgAccess, Principal, RequestContext
from app.state import AppState

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token", auto_error=False)
api_key_scheme = APIKeyHeader(
    name="X-API-Key", auto_error=False, description="Organisation API key (vg_live_...)"
)


def get_state(request: Request) -> AppState:
    state: AppState = request.app.state.vg
    return state


StateDep = Annotated[AppState, Depends(get_state)]


async def get_session(state: StateDep) -> AsyncIterator[AsyncSession]:
    async with state.sessionmaker() as session:
        yield session


SessionDep = Annotated[AsyncSession, Depends(get_session)]


def get_request_context(request: Request, state: StateDep) -> RequestContext:
    ua = request.headers.get("user-agent")
    return RequestContext(
        ip=client_ip(request.scope, state.settings.trusted_proxy_hops),
        user_agent=ua[:512] if ua else None,
        request_id=request_id_ctx.get(),
    )


CtxDep = Annotated[RequestContext, Depends(get_request_context)]


async def get_principal(
    state: StateDep,
    session: SessionDep,
    bearer: Annotated[str | None, Security(oauth2_scheme)],
    x_api_key: Annotated[str | None, Security(api_key_scheme)],
) -> Principal:
    raw = x_api_key or bearer
    if not raw:
        raise NotAuthenticated()
    if api_keys.looks_like_api_key(raw):
        key = await api_keys.authenticate(state, session, raw)
        return Principal(api_key=key)

    claims = state.tokens.decode(raw, TokenType.ACCESS)
    try:
        user_id = uuid.UUID(claims.sub)
    except ValueError as exc:
        raise InvalidToken() from exc
    user = await session.get(User, user_id)
    if user is None or not user.is_active:
        raise InvalidToken()
    if user.tokens_valid_after is not None and claims.iat < user.tokens_valid_after:
        raise InvalidToken("Token has been revoked.")
    return Principal(user=user, amr=claims.amr)


PrincipalDep = Annotated[Principal, Depends(get_principal)]


async def get_current_user(principal: PrincipalDep) -> User:
    if principal.user is None:
        raise PermissionDenied("This endpoint requires a user session, not an API key.")
    return principal.user


CurrentUser = Annotated[User, Depends(get_current_user)]


def user_ctx(ctx: CtxDep, user: CurrentUser) -> RequestContext:
    return ctx.as_actor(ActorType.USER, user.id)


UserCtx = Annotated[RequestContext, Depends(user_ctx)]


def require(permission: Permission) -> Callable[..., Awaitable[OrgAccess]]:
    """Build a dependency that authorises ``permission`` on the path's ``org_id``.

    Unknown orgs and orgs the caller is not a member of both return 404, so the
    API never confirms the existence of another tenant's resources (BOLA / IDOR).
    """

    async def dependency(
        org_id: Annotated[uuid.UUID, Path()],
        principal: PrincipalDep,
        session: SessionDep,
        ctx: CtxDep,
    ) -> OrgAccess:
        org = await session.get(Organization, org_id)
        if org is None or org.deleted_at is not None:
            raise NotFound("Organisation not found.")

        role: Role | None
        if principal.api_key is not None:
            if principal.api_key.org_id != org_id:
                raise NotFound("Organisation not found.")
            role = None
            perms = frozenset(Permission(s) for s in principal.api_key.scopes) & API_KEY_GRANTABLE
        else:
            assert principal.user is not None  # noqa: S101
            membership = (
                await session.execute(
                    select(Membership).where(
                        Membership.org_id == org_id, Membership.user_id == principal.user.id
                    )
                )
            ).scalar_one_or_none()
            if membership is None:
                raise NotFound("Organisation not found.")
            role = Role(membership.role)
            perms = ROLE_PERMISSIONS[role]

        if permission not in perms:
            raise PermissionDenied(f"Missing permission '{permission.value}'.")
        return OrgAccess(
            principal=principal,
            org_id=org_id,
            role=role,
            permissions=perms,
            ctx=ctx.as_actor(principal.actor_type, principal.actor_id),
        )

    dependency.__name__ = f"require_{permission.name.lower()}"
    return dependency
