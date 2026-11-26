from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Response, status
from fastapi.security import OAuth2PasswordRequestForm

from app.api.deps import CtxDep, CurrentUser, SessionDep, StateDep, UserCtx
from app.core.errors import MfaRequired
from app.schemas.auth import (
    ChangePasswordIn,
    LoginIn,
    MfaChallenge,
    MfaLoginIn,
    RecoveryCodesOut,
    RefreshIn,
    SignupIn,
    TokenPair,
    TotpCodeIn,
    TotpDisableIn,
    TotpSetupOut,
    VerifyEmailIn,
)
from app.schemas.common import Message
from app.services import auth

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/signup", status_code=status.HTTP_202_ACCEPTED, response_model=Message)
async def signup(body: SignupIn, state: StateDep, session: SessionDep, ctx: CtxDep) -> Message:
    """Register. The response is identical for new and existing addresses."""
    await auth.signup(
        state, session, ctx, email=str(body.email), password=body.password, full_name=body.full_name
    )
    return Message(detail="If the address can be registered, a verification email has been sent.")


@router.post("/login", response_model=TokenPair | MfaChallenge)
async def login(
    body: LoginIn, state: StateDep, session: SessionDep, ctx: CtxDep
) -> TokenPair | MfaChallenge:
    result = await auth.login(state, session, ctx, email=str(body.email), password=body.password)
    if result.challenge is not None:
        return result.challenge
    assert result.tokens is not None  # noqa: S101
    return result.tokens


@router.post("/login/mfa", response_model=TokenPair)
async def login_mfa(
    body: MfaLoginIn, state: StateDep, session: SessionDep, ctx: CtxDep
) -> TokenPair:
    return await auth.login_mfa(state, session, ctx, mfa_token=body.mfa_token, code=body.code)


@router.post("/token", response_model=TokenPair, include_in_schema=True)
async def oauth2_token(
    form: Annotated[OAuth2PasswordRequestForm, Depends()],
    state: StateDep,
    session: SessionDep,
    ctx: CtxDep,
) -> TokenPair:
    """OAuth2 password grant (used by the Swagger "Authorize" button)."""
    result = await auth.login(state, session, ctx, email=form.username, password=form.password)
    if result.tokens is None:
        raise MfaRequired("Account has 2FA enabled; use /auth/login then /auth/login/mfa.")
    return result.tokens


@router.post("/refresh", response_model=TokenPair)
async def refresh(body: RefreshIn, state: StateDep, session: SessionDep, ctx: CtxDep) -> TokenPair:
    return await auth.refresh(state, session, ctx, body.refresh_token)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(body: RefreshIn, state: StateDep, session: SessionDep, ctx: CtxDep) -> Response:
    await auth.logout(state, session, ctx, body.refresh_token)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/logout-all", status_code=status.HTTP_204_NO_CONTENT)
async def logout_all(
    state: StateDep, session: SessionDep, ctx: UserCtx, user: CurrentUser
) -> Response:
    await auth.logout_all(state, session, ctx, user)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/verify-email", status_code=status.HTTP_204_NO_CONTENT)
async def verify_email(
    body: VerifyEmailIn, state: StateDep, session: SessionDep, ctx: CtxDep
) -> Response:
    await auth.verify_email(state, session, ctx, body.token)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/verify-email/resend", status_code=status.HTTP_202_ACCEPTED, response_model=Message)
async def resend_verification(
    state: StateDep, session: SessionDep, ctx: UserCtx, user: CurrentUser
) -> Message:
    await auth.resend_verification(state, session, ctx, user)
    return Message(detail="If your address is unverified, a new email has been sent.")


@router.post("/password/change", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(
    body: ChangePasswordIn, state: StateDep, session: SessionDep, ctx: UserCtx, user: CurrentUser
) -> Response:
    await auth.change_password(
        state,
        session,
        ctx,
        user,
        current_password=body.current_password,
        new_password=body.new_password,
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/2fa/setup", response_model=TotpSetupOut)
async def totp_setup(
    state: StateDep, session: SessionDep, ctx: UserCtx, user: CurrentUser
) -> TotpSetupOut:
    secret, uri = await auth.totp_setup(state, session, ctx, user)
    return TotpSetupOut(secret=secret, otpauth_uri=uri)


@router.post("/2fa/enable", response_model=RecoveryCodesOut)
async def totp_enable(
    body: TotpCodeIn, state: StateDep, session: SessionDep, ctx: UserCtx, user: CurrentUser
) -> RecoveryCodesOut:
    codes = await auth.totp_enable(state, session, ctx, user, body.code)
    return RecoveryCodesOut(recovery_codes=codes)


@router.post("/2fa/disable", status_code=status.HTTP_204_NO_CONTENT)
async def totp_disable(
    body: TotpDisableIn, state: StateDep, session: SessionDep, ctx: UserCtx, user: CurrentUser
) -> Response:
    await auth.totp_disable(state, session, ctx, user, password=body.password, code=body.code)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
