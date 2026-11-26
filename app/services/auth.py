"""Authentication: signup, login (+MFA), refresh-token rotation, email verification."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pyotp
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.concurrency import run_in_threadpool

from app.core.crypto import EncryptedPayload
from app.core.email import EmailMessage
from app.core.errors import (
    Conflict,
    InvalidCredentials,
    InvalidToken,
    ValidationFailed,
)
from app.core.security import (
    constant_time_equals,
    generate_recovery_code,
    generate_token,
    normalize_recovery_code,
    sha256_hex,
)
from app.core.tokens import TokenType
from app.db.base import utcnow
from app.db.models import EmailToken, RecoveryCode, RefreshToken, User
from app.schemas.auth import MfaChallenge, TokenPair
from app.services import audit
from app.services.context import ActorType, RequestContext
from app.state import AppState

REFRESH_PREFIX = "vgr_"
VERIFY_EMAIL = "verify_email"
RECOVERY_CODE_COUNT = 10
TOTP_ISSUER = "vaultgate"


def normalize_email(email: str) -> str:
    return email.strip().lower()


def _check_password_policy(state: AppState, password: str, email: str) -> None:
    problems = state.policy.violations(password, email=email)
    if problems:
        raise ValidationFailed(
            "Password does not meet the policy.",
            extra={
                "errors": [
                    {"loc": ["body", "password"], "msg": f"Password {p}", "type": "password_policy"}
                    for p in problems
                ]
            },
        )


async def _hash_password(state: AppState, password: str) -> str:
    # Argon2 is deliberately CPU/memory heavy - keep it off the event loop.
    return await run_in_threadpool(state.hasher.hash, password)


async def _verify_password(state: AppState, password_hash: str | None, password: str) -> bool:
    return await run_in_threadpool(state.hasher.verify, password_hash, password)


# --------------------------------------------------------------------------- signup


async def signup(
    state: AppState,
    session: AsyncSession,
    ctx: RequestContext,
    *,
    email: str,
    password: str,
    full_name: str,
) -> None:
    """Register an account.

    The response is identical whether or not the address is already registered
    (prevents account enumeration). An existing owner instead receives a
    "someone tried to sign up with your address" notice.
    """
    email = normalize_email(email)
    _check_password_policy(state, password, email)
    password_hash = await _hash_password(state, password)  # hash in both paths: equal timing

    existing = (await session.execute(select(User).where(User.email == email))).scalar_one_or_none()
    if existing is not None:
        await state.email.send(
            EmailMessage(
                to=email,
                subject="Sign-up attempt on your vaultgate account",
                body="Someone tried to create an account with this address. "
                "If this was you, sign in or reset your password instead.",
            )
        )
        return

    user = User(email=email, full_name=full_name, password_hash=password_hash)
    session.add(user)
    await session.flush()
    await audit.record(
        session,
        ctx.as_actor(ActorType.USER, user.id),
        "user.signup",
        target_type="user",
        target_id=user.id,
    )
    raw = await _create_email_token(state, session, user)
    await session.commit()
    await _send_verification(state, user.email, raw)


async def _create_email_token(state: AppState, session: AsyncSession, user: User) -> str:
    raw = generate_token()
    session.add(
        EmailToken(
            user_id=user.id,
            purpose=VERIFY_EMAIL,
            token_hash=sha256_hex(raw),
            expires_at=utcnow() + timedelta(seconds=state.settings.email_token_ttl_seconds),
        )
    )
    await session.flush()
    return raw


async def _send_verification(state: AppState, email: str, raw: str) -> None:
    link = f"{state.settings.public_base_url}/verify-email?token={raw}"
    await state.email.send(
        EmailMessage(
            to=email,
            subject="Verify your vaultgate email address",
            body=(
                f"Confirm your address: {link}\n"
                f"Or POST this token to /api/v1/auth/verify-email: {raw}"
            ),
        )
    )


async def resend_verification(
    state: AppState, session: AsyncSession, ctx: RequestContext, user: User
) -> None:
    if user.email_verified_at is not None:
        return
    await session.execute(
        delete(EmailToken).where(EmailToken.user_id == user.id, EmailToken.used_at.is_(None))
    )
    raw = await _create_email_token(state, session, user)
    await audit.record(
        session, ctx, "user.verification_resent", target_type="user", target_id=user.id
    )
    await session.commit()
    await _send_verification(state, user.email, raw)


async def verify_email(
    state: AppState, session: AsyncSession, ctx: RequestContext, raw: str
) -> None:
    tok = (
        await session.execute(
            select(EmailToken).where(
                EmailToken.token_hash == sha256_hex(raw), EmailToken.purpose == VERIFY_EMAIL
            )
        )
    ).scalar_one_or_none()
    now = utcnow()
    if tok is None or tok.used_at is not None or tok.expires_at <= now:
        raise InvalidToken("Verification token is invalid or expired.")
    user = await session.get(User, tok.user_id)
    if user is None:  # pragma: no cover - FK cascade makes this unreachable
        raise InvalidToken()
    tok.used_at = now
    user.email_verified_at = user.email_verified_at or now
    await audit.record(
        session,
        ctx.as_actor(ActorType.USER, user.id),
        "user.email_verified",
        target_type="user",
        target_id=user.id,
    )
    await session.commit()


# --------------------------------------------------------------------------- login


@dataclass(frozen=True, slots=True)
class LoginResult:
    tokens: TokenPair | None = None
    challenge: MfaChallenge | None = None


async def _register_failure(
    state: AppState, session: AsyncSession, ctx: RequestContext, user: User | None, reason: str
) -> None:
    details: dict[str, object] = {"reason": reason}
    if user is not None:
        user.failed_login_count += 1
        if user.failed_login_count >= state.settings.lockout_threshold:
            user.locked_until = utcnow() + timedelta(seconds=state.settings.lockout_seconds)
            user.failed_login_count = 0
            details["locked"] = True
            await audit.record(
                session, ctx, "auth.account_locked", target_type="user", target_id=user.id
            )
    await audit.record(
        session,
        ctx,
        "auth.login_failed",
        target_type="user",
        target_id=user.id if user else None,
        details=details,
    )
    await session.commit()
    state.metrics.logins.labels(outcome=reason).inc()


async def login(
    state: AppState, session: AsyncSession, ctx: RequestContext, *, email: str, password: str
) -> LoginResult:
    email = normalize_email(email)
    user = (await session.execute(select(User).where(User.email == email))).scalar_one_or_none()
    now = utcnow()

    if user is not None and user.locked_until is not None and user.locked_until > now:
        # Burn the same CPU as a real check and answer identically: a lockout must
        # not become an account-existence oracle.
        await _verify_password(state, None, password)
        await audit.record(
            session,
            ctx,
            "auth.login_failed",
            target_type="user",
            target_id=user.id,
            details={"reason": "locked"},
        )
        await session.commit()
        state.metrics.logins.labels(outcome="locked").inc()
        raise InvalidCredentials()

    ok = await _verify_password(state, user.password_hash if user else None, password)
    if user is None or not ok or not user.is_active:
        reason = "unknown_user" if user is None else ("bad_password" if not ok else "inactive")
        await _register_failure(state, session, ctx, user, reason)
        raise InvalidCredentials()

    user.failed_login_count = 0
    user.locked_until = None
    if state.hasher.needs_rehash(user.password_hash):
        user.password_hash = await _hash_password(state, password)

    if user.totp_enabled_at is not None:
        await session.commit()
        token, _ = state.tokens.issue(
            str(user.id), TokenType.MFA, state.settings.mfa_token_ttl_seconds, amr=["pwd"]
        )
        state.metrics.logins.labels(outcome="mfa_challenge").inc()
        return LoginResult(
            challenge=MfaChallenge(mfa_token=token, expires_in=state.settings.mfa_token_ttl_seconds)
        )

    pair = await issue_session(state, session, ctx, user, amr=["pwd"])
    return LoginResult(tokens=pair)


async def login_mfa(
    state: AppState, session: AsyncSession, ctx: RequestContext, *, mfa_token: str, code: str
) -> TokenPair:
    claims = state.tokens.decode(mfa_token, TokenType.MFA)
    user = await session.get(User, uuid.UUID(claims.sub))
    if user is None or not user.is_active or user.totp_enabled_at is None:
        raise InvalidToken()
    if user.locked_until is not None and user.locked_until > utcnow():
        raise InvalidCredentials()
    method = await verify_second_factor(state, session, user, code)
    if method is None:
        await _register_failure(state, session, ctx, user, "bad_otp")
        raise InvalidCredentials("Invalid authentication code.")
    user.failed_login_count = 0
    return await issue_session(state, session, ctx, user, amr=["pwd", method])


# --------------------------------------------------------------------------- sessions


async def issue_session(
    state: AppState,
    session: AsyncSession,
    ctx: RequestContext,
    user: User,
    *,
    amr: list[str],
    family_id: uuid.UUID | None = None,
    parent_id: uuid.UUID | None = None,
) -> TokenPair:
    access, _ = state.tokens.issue(
        str(user.id), TokenType.ACCESS, state.settings.access_token_ttl_seconds, amr=amr
    )
    raw_refresh = REFRESH_PREFIX + generate_token()
    now = utcnow()
    session.add(
        RefreshToken(
            user_id=user.id,
            family_id=family_id or uuid.uuid4(),
            parent_id=parent_id,
            token_hash=sha256_hex(raw_refresh),
            expires_at=now + timedelta(seconds=state.settings.refresh_token_ttl_seconds),
            ip=ctx.ip,
            user_agent=(ctx.user_agent or "")[:512] or None,
        )
    )
    user_ctx = ctx.as_actor(ActorType.USER, user.id)
    if family_id is None:
        user.last_login_at = now
        await audit.record(
            session,
            user_ctx,
            "auth.login_succeeded",
            target_type="user",
            target_id=user.id,
            details={"amr": amr},
        )
        state.metrics.logins.labels(outcome="success").inc()
    else:
        await audit.record(
            session, user_ctx, "auth.token_refreshed", target_type="session", target_id=family_id
        )
    await session.commit()
    return TokenPair(
        access_token=access,
        refresh_token=raw_refresh,
        expires_in=state.settings.access_token_ttl_seconds,
    )


async def _revoke_family(session: AsyncSession, family_id: uuid.UUID, reason: str) -> int:
    res = await session.execute(
        update(RefreshToken)
        .where(RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=utcnow(), revoke_reason=reason)
    )
    return int(getattr(res, "rowcount", 0) or 0)


async def refresh(
    state: AppState, session: AsyncSession, ctx: RequestContext, raw: str
) -> TokenPair:
    """Rotate a refresh token. Re-presentation of a spent token revokes the family."""
    tok = (
        await session.execute(
            select(RefreshToken).where(RefreshToken.token_hash == sha256_hex(raw))
        )
    ).scalar_one_or_none()
    if tok is None:
        raise InvalidToken()

    async def _reuse_detected() -> InvalidToken:
        revoked = await _revoke_family(session, tok.family_id, "reuse_detected")
        await audit.record(
            session,
            ctx.as_actor(ActorType.USER, tok.user_id),
            "auth.refresh_reuse_detected",
            target_type="session",
            target_id=tok.family_id,
            details={"revoked_tokens": revoked},
        )
        await session.commit()
        state.metrics.refresh_reuse.inc()
        return InvalidToken("Refresh token reuse detected; all sessions in this family revoked.")

    if tok.used_at is not None or tok.revoked_at is not None:
        raise await _reuse_detected()
    if tok.expires_at <= utcnow():
        raise InvalidToken()

    # Atomic compare-and-set: only one concurrent caller can spend this token.
    res = await session.execute(
        update(RefreshToken)
        .where(
            RefreshToken.id == tok.id,
            RefreshToken.used_at.is_(None),
            RefreshToken.revoked_at.is_(None),
        )
        .values(used_at=utcnow())
    )
    if int(getattr(res, "rowcount", 0) or 0) != 1:  # pragma: no cover - needs a true race
        raise await _reuse_detected()

    user = await session.get(User, tok.user_id)
    if user is None or not user.is_active:
        raise InvalidToken()
    return await issue_session(
        state, session, ctx, user, amr=["pwd"], family_id=tok.family_id, parent_id=tok.id
    )


async def logout(state: AppState, session: AsyncSession, ctx: RequestContext, raw: str) -> None:
    tok = (
        await session.execute(
            select(RefreshToken).where(RefreshToken.token_hash == sha256_hex(raw))
        )
    ).scalar_one_or_none()
    if tok is None:
        return  # idempotent: never reveal whether a token existed
    await _revoke_family(session, tok.family_id, "logout")
    await audit.record(
        session,
        ctx.as_actor(ActorType.USER, tok.user_id),
        "auth.logout",
        target_type="session",
        target_id=tok.family_id,
    )
    await session.commit()


async def revoke_all_sessions(session: AsyncSession, user: User, reason: str) -> None:
    await session.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user.id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=utcnow(), revoke_reason=reason)
    )
    # JWTs have second resolution; anything issued before this second is dead.
    user.tokens_valid_after = datetime.now(UTC).replace(microsecond=0)


async def logout_all(
    state: AppState, session: AsyncSession, ctx: RequestContext, user: User
) -> None:
    await revoke_all_sessions(session, user, "logout_all")
    await audit.record(session, ctx, "auth.logout_all", target_type="user", target_id=user.id)
    await session.commit()


async def change_password(
    state: AppState,
    session: AsyncSession,
    ctx: RequestContext,
    user: User,
    *,
    current_password: str,
    new_password: str,
) -> None:
    if not await _verify_password(state, user.password_hash, current_password):
        raise InvalidCredentials("Current password is incorrect.")
    _check_password_policy(state, new_password, user.email)
    if await _verify_password(state, user.password_hash, new_password):
        raise ValidationFailed("New password must differ from the current one.")
    user.password_hash = await _hash_password(state, new_password)
    await revoke_all_sessions(session, user, "password_changed")
    await audit.record(session, ctx, "user.password_changed", target_type="user", target_id=user.id)
    await session.commit()


# --------------------------------------------------------------------------- TOTP


def totp_aad(user_id: uuid.UUID) -> bytes:
    return f"vaultgate:totp:{user_id}".encode()


def _load_totp(state: AppState, user: User) -> pyotp.TOTP:
    assert user.totp_secret_enc is not None  # noqa: S101
    secret = state.cipher.decrypt(
        EncryptedPayload.from_blob(user.totp_secret_enc), totp_aad(user.id)
    )
    return pyotp.TOTP(secret.decode())


async def totp_setup(
    state: AppState, session: AsyncSession, ctx: RequestContext, user: User
) -> tuple[str, str]:
    if user.totp_enabled_at is not None:
        raise Conflict("Two-factor authentication is already enabled.")
    secret = pyotp.random_base32()
    user.totp_secret_enc = state.cipher.encrypt(secret.encode(), totp_aad(user.id)).to_blob()
    await audit.record(
        session, ctx, "user.mfa_setup_started", target_type="user", target_id=user.id
    )
    await session.commit()
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name=TOTP_ISSUER)
    return secret, uri


def _match_totp(state: AppState, user: User, code: str, now: datetime | None = None) -> int | None:
    """Return the matching time-step counter (+/- 1 step drift), rejecting replays."""
    if not code.isdigit() or len(code) != 6:
        return None
    totp = _load_totp(state, user)
    current = totp.timecode(now or datetime.now(UTC))
    last = user.totp_last_counter if user.totp_last_counter is not None else -1
    for counter in (current - 1, current, current + 1):
        if counter > last and constant_time_equals(totp.generate_otp(counter), code):
            return counter
    return None


async def totp_enable(
    state: AppState, session: AsyncSession, ctx: RequestContext, user: User, code: str
) -> list[str]:
    if user.totp_enabled_at is not None:
        raise Conflict("Two-factor authentication is already enabled.")
    if user.totp_secret_enc is None:
        raise ValidationFailed("Call /auth/2fa/setup first.")
    counter = _match_totp(state, user, code)
    if counter is None:
        raise ValidationFailed("Invalid authentication code.")
    user.totp_last_counter = counter
    user.totp_enabled_at = utcnow()
    codes = await _regenerate_recovery_codes(session, user)
    await audit.record(session, ctx, "user.mfa_enabled", target_type="user", target_id=user.id)
    await session.commit()
    return codes


async def _regenerate_recovery_codes(session: AsyncSession, user: User) -> list[str]:
    await session.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))
    codes = [generate_recovery_code() for _ in range(RECOVERY_CODE_COUNT)]
    session.add_all(
        RecoveryCode(user_id=user.id, code_hash=sha256_hex(normalize_recovery_code(c)))
        for c in codes
    )
    await session.flush()
    return codes


async def verify_second_factor(
    state: AppState, session: AsyncSession, user: User, code: str
) -> str | None:
    """Return the AMR value used ("otp" / "recovery") or ``None`` if invalid."""
    code = code.strip()
    counter = _match_totp(state, user, code)
    if counter is not None:
        user.totp_last_counter = counter
        return "otp"
    digest = sha256_hex(normalize_recovery_code(code))
    rows = (
        (
            await session.execute(
                select(RecoveryCode).where(
                    RecoveryCode.user_id == user.id, RecoveryCode.used_at.is_(None)
                )
            )
        )
        .scalars()
        .all()
    )
    match = None
    for rc in rows:  # scan all rows: no early exit, constant-time per comparison
        if constant_time_equals(rc.code_hash, digest):
            match = rc
    if match is not None:
        match.used_at = utcnow()
        return "recovery"
    return None


async def totp_disable(
    state: AppState,
    session: AsyncSession,
    ctx: RequestContext,
    user: User,
    *,
    password: str,
    code: str,
) -> None:
    if user.totp_enabled_at is None:
        raise Conflict("Two-factor authentication is not enabled.")
    if not await _verify_password(state, user.password_hash, password):
        raise InvalidCredentials("Password is incorrect.")
    if await verify_second_factor(state, session, user, code) is None:
        raise InvalidCredentials("Invalid authentication code.")
    user.totp_enabled_at = None
    user.totp_secret_enc = None
    user.totp_last_counter = None
    await session.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))
    await audit.record(session, ctx, "user.mfa_disabled", target_type="user", target_id=user.id)
    await session.commit()
