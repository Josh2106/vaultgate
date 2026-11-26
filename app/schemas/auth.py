from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import EmailStr, Field, StringConstraints

from app.schemas.common import OutSchema, Schema

Password = Annotated[str, StringConstraints(min_length=1, max_length=128, strip_whitespace=False)]
OtpCode = Annotated[str, StringConstraints(min_length=6, max_length=16)]


class SignupIn(Schema):
    email: EmailStr
    password: Password
    full_name: Annotated[str, StringConstraints(max_length=200)] = ""


class LoginIn(Schema):
    email: EmailStr
    password: Password


class MfaLoginIn(Schema):
    mfa_token: str = Field(max_length=2048)
    code: OtpCode = Field(description="6-digit TOTP code or a recovery code (XXXXX-XXXXX)")


class RefreshIn(Schema):
    refresh_token: str = Field(min_length=10, max_length=256)


class TokenPair(OutSchema):
    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"  # noqa: S105 - OAuth2 token type, not a secret
    expires_in: int


class MfaChallenge(OutSchema):
    mfa_required: Literal[True] = True
    mfa_token: str
    expires_in: int


class VerifyEmailIn(Schema):
    token: str = Field(min_length=10, max_length=256)


class ChangePasswordIn(Schema):
    current_password: Password
    new_password: Password


class TotpSetupOut(OutSchema):
    secret: str
    otpauth_uri: str


class TotpCodeIn(Schema):
    code: OtpCode


class TotpDisableIn(Schema):
    password: Password
    code: OtpCode


class RecoveryCodesOut(OutSchema):
    recovery_codes: list[str] = Field(description="Shown once. Store them somewhere safe.")


class UserOut(OutSchema):
    id: uuid.UUID
    email: str
    full_name: str
    email_verified: bool
    mfa_enabled: bool
    created_at: datetime


class Jwks(OutSchema):
    keys: list[dict[str, str]]
