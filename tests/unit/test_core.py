"""Unit tests for security primitives, tokens, config, permissions, pagination and helpers."""

from __future__ import annotations

import base64
import itertools
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from app.core.config import Environment, Settings
from app.core.errors import InvalidToken, ValidationFailed
from app.core.logging import _redact
from app.core.net import client_ip
from app.core.permissions import (
    API_KEY_GRANTABLE,
    ROLE_PERMISSIONS,
    Permission,
    Role,
    role_has,
)
from app.core.security import (
    PasswordHasher,
    PasswordPolicy,
    constant_time_equals,
    generate_recovery_code,
    normalize_recovery_code,
    sha256_hex,
)
from app.core.tokens import ALGORITHM, KeyRing, TokenService, TokenType
from app.services.api_keys import parse_key
from app.services.pagination import (
    clamp_limit,
    decode_seq_cursor,
    decode_time_cursor,
    encode_seq_cursor,
    encode_time_cursor,
)

# ------------------------------------------------------------------ passwords


@pytest.fixture(scope="module")
def hasher() -> PasswordHasher:
    s = Settings(
        _env_file=None,
        environment=Environment.TEST,
        argon2_time_cost=1,
        argon2_memory_cost_kib=1024,
        argon2_parallelism=1,
    )
    return PasswordHasher(s)


def test_argon2id_hash_and_verify(hasher: PasswordHasher) -> None:
    h = hasher.hash("pw-123456789")
    assert h.startswith("$argon2id$")
    assert hasher.verify(h, "pw-123456789")
    assert not hasher.verify(h, "pw-wrong")
    assert not hasher.verify("not-a-hash", "pw")
    assert not hasher.verify(None, "anything")  # dummy path never succeeds
    assert not hasher.needs_rehash(h)


def test_rehash_detected_when_params_change(hasher: PasswordHasher) -> None:
    stronger = PasswordHasher(
        Settings(
            _env_file=None,
            argon2_time_cost=2,
            argon2_memory_cost_kib=2048,
            argon2_parallelism=1,
        )
    )
    assert stronger.needs_rehash(hasher.hash("x" * 12))


def test_password_policy_accepts_passphrase() -> None:
    assert PasswordPolicy().violations("Correct-Horse-42!", email="a@b.c") == []
    assert PasswordPolicy().violations("x" * 200)


def test_helpers() -> None:
    assert constant_time_equals("abc", b"abc")
    assert not constant_time_equals("abc", "abd")
    assert len(sha256_hex("x")) == 64
    code = generate_recovery_code()
    assert len(code) == 11 and code[5] == "-"
    assert normalize_recovery_code(" ab cd-e ") == "ABCD-E"


# ------------------------------------------------------------------ JWT


@pytest.fixture
def ring(tmp_path: Path) -> KeyRing:
    return KeyRing.from_directory(tmp_path, auto_generate=True)


def _svc(ring: KeyRing) -> TokenService:
    return TokenService(ring, issuer="vaultgate", audience="vaultgate-api")


def test_issue_and_decode(ring: KeyRing) -> None:
    svc = _svc(ring)
    token, claims = svc.issue("user-1", TokenType.ACCESS, 300, amr=["pwd", "otp"])
    assert jwt.get_unverified_header(token)["kid"] == ring.active_kid
    decoded = svc.decode(token, TokenType.ACCESS)
    assert decoded.sub == "user-1" and decoded.amr == ["pwd", "otp"]
    assert decoded.jti == claims.jti


def test_token_type_confusion_rejected(ring: KeyRing) -> None:
    svc = _svc(ring)
    mfa, _ = svc.issue("u", TokenType.MFA, 60)
    with pytest.raises(InvalidToken):
        svc.decode(mfa, TokenType.ACCESS)


def test_wrong_audience_or_issuer(ring: KeyRing) -> None:
    token, _ = TokenService(ring, issuer="evil", audience="vaultgate-api").issue(
        "u", TokenType.ACCESS, 60
    )
    with pytest.raises(InvalidToken):
        _svc(ring).decode(token, TokenType.ACCESS)


def test_expired_token(ring: KeyRing) -> None:
    now = int(datetime.now(UTC).timestamp())
    token = ring.sign(
        {
            "iss": "vaultgate",
            "aud": "vaultgate-api",
            "sub": "u",
            "typ": "access",
            "jti": "j",
            "iat": now - 120,
            "nbf": now - 120,
            "exp": now - 60,
        }
    )
    with pytest.raises(InvalidToken):
        _svc(ring).decode(token, TokenType.ACCESS)


def _b64(d: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


@pytest.mark.parametrize(
    "header",
    [
        {"alg": "none"},
        {"alg": "HS256", "kid": "x"},
        {"alg": ALGORITHM, "kid": "unknown"},
        {"alg": ALGORITHM},
    ],
)
def test_forged_headers_rejected(ring: KeyRing, header: dict[str, Any]) -> None:
    forged = f"{_b64(header)}.{_b64({'sub': 'admin'})}.c2ln"
    with pytest.raises(InvalidToken):
        _svc(ring).decode(forged, TokenType.ACCESS)


def test_signature_from_foreign_key_rejected(ring: KeyRing) -> None:
    now = int(datetime.now(UTC).timestamp())
    claims = {
        "iss": "vaultgate",
        "aud": "vaultgate-api",
        "sub": "u",
        "typ": "access",
        "jti": "j",
        "iat": now,
        "nbf": now,
        "exp": now + 60,
    }
    forged = jwt.encode(
        claims, Ed25519PrivateKey.generate(), algorithm=ALGORITHM, headers={"kid": ring.active_kid}
    )
    with pytest.raises(InvalidToken):
        _svc(ring).decode(forged, TokenType.ACCESS)
    with pytest.raises(InvalidToken):
        _svc(ring).decode("not.a.jwt", TokenType.ACCESS)


def test_keyring_errors(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError):
        KeyRing.from_directory(tmp_path / "empty")
    with pytest.raises(ValueError, match="not present"):
        KeyRing({}, "missing")
    (tmp_path / "bad").mkdir()
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    (tmp_path / "bad" / "k1.pem").write_bytes(pem)
    with pytest.raises(TypeError):
        KeyRing.from_directory(tmp_path / "bad")


# ------------------------------------------------------------------ config


def test_production_requires_safe_settings() -> None:
    with pytest.raises(ValidationError) as exc:
        Settings(_env_file=None, environment=Environment.PRODUCTION)
    msg = str(exc.value)
    for fragment in ("SQLite", "JWT_AUTO_GENERATE", "MASTER_KEY_AUTO_GENERATE", "HSTS"):
        assert fragment in msg
    ok = Settings(
        _env_file=None,
        environment=Environment.PRODUCTION,
        database_url="postgresql+asyncpg://u:p@db/vg",
        jwt_auto_generate=False,
        master_key_auto_generate=False,
        hsts_enabled=True,
    )
    assert ok.api_key_prefix == "vg_live_" and ok.is_production


def test_cors_parsing_and_wildcard_rejected() -> None:
    raw: dict[str, Any] = {"cors_origins": "https://a.com, https://b.com"}  # as from env
    s = Settings(_env_file=None, **raw)
    assert s.cors_origins == ["https://a.com", "https://b.com"]
    with pytest.raises(ValidationError, match="Wildcard"):
        Settings(_env_file=None, cors_origins=["*"])


# ------------------------------------------------------------------ RBAC invariants


def test_roles_are_strictly_nested() -> None:
    ordered = sorted(Role, key=lambda r: r.rank)
    for lower, higher in itertools.pairwise(ordered):
        assert ROLE_PERMISSIONS[lower] < ROLE_PERMISSIONS[higher]


def test_only_owner_can_delete_org() -> None:
    assert [r for r in Role if role_has(r, Permission.ORG_DELETE)] == [Role.OWNER]


def test_viewer_cannot_decrypt() -> None:
    assert not role_has(Role.VIEWER, Permission.SECRET_READ)
    assert role_has(Role.VIEWER, Permission.SECRET_LIST)


def test_api_keys_cannot_hold_governance_permissions() -> None:
    governance = {
        Permission.MEMBER_MANAGE,
        Permission.APIKEY_MANAGE,
        Permission.ORG_DELETE,
        Permission.ORG_UPDATE,
    }
    assert not (API_KEY_GRANTABLE & governance)


# ------------------------------------------------------------------ pagination / misc


def test_cursors_roundtrip() -> None:
    import uuid

    ts, rid = datetime.now(UTC), uuid.uuid4()
    assert decode_time_cursor(encode_time_cursor(ts, rid)) == (ts, rid)
    assert decode_seq_cursor(encode_seq_cursor(42)) == 42
    for bad in (
        "%%%",
        base64.urlsafe_b64encode(b"[1]").decode(),
        base64.urlsafe_b64encode(b'{"t": "x"}').decode(),
    ):
        with pytest.raises(ValidationFailed):
            decode_time_cursor(bad)
    with pytest.raises(ValidationFailed):
        decode_seq_cursor(base64.urlsafe_b64encode(b'{"s": -1}').decode())
    assert clamp_limit(None) == 50 and clamp_limit(1000) == 100 and clamp_limit(0) == 1


def test_client_ip_trusts_only_configured_hops() -> None:
    scope: dict[str, Any] = {
        "client": ("10.0.0.5", 1),
        "headers": [(b"x-forwarded-for", b"6.6.6.6, 1.2.3.4")],
    }
    assert client_ip(scope, 0) == "10.0.0.5"  # spoofable header ignored
    assert client_ip(scope, 1) == "1.2.3.4"
    assert client_ip(scope, 2) == "6.6.6.6"
    assert client_ip(scope, 5) == "6.6.6.6"
    assert client_ip({"headers": []}, 0) == "unknown"


def test_log_redaction() -> None:
    event = {
        "event": "x",
        "password": "p",
        "refresh_token": "t",
        "Authorization": "a",
        "value": "v",
        "status_code": 200,
        "user_id": "u",
    }
    out = _redact(None, "info", event)
    assert out["password"] == out["refresh_token"] == out["Authorization"] == "[REDACTED]"
    assert out["value"] == "[REDACTED]"
    assert out["status_code"] == 200 and out["user_id"] == "u" and out["event"] == "x"


def test_api_key_parsing() -> None:
    assert parse_key("vg_test_0123456789ab_secret", "vg_test_") == "0123456789ab"
    assert parse_key("vg_live_0123456789ab_secret", "vg_test_") is None
    assert parse_key("vg_test_0123456789ab-secret", "vg_test_") is None
    assert parse_key("vg_test_0123456789aZ_secret", "vg_test_") is None
