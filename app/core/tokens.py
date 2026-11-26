"""EdDSA (Ed25519) JWT signing with a rotating key ring.

* Every token carries a ``kid`` header naming the key that signed it.
* The key ring holds one *active* signing key plus any number of older keys
  that remain valid for verification until they are removed - this is what
  makes zero-downtime rotation possible (see ``docs/adr/0004``).
* Keys are PEM files named ``<kid>.pem`` in ``VG_JWT_KEYS_DIR`` - the natural
  shape for a Kubernetes Secret volume mount.
* Public keys are published at ``/.well-known/jwks.json`` so other services can
  verify tokens without ever holding signing material.
"""

from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from app.core.errors import InvalidToken

ALGORITHM = "EdDSA"


class TokenType(StrEnum):
    ACCESS = "access"
    MFA = "mfa"


@dataclass(frozen=True, slots=True)
class TokenClaims:
    sub: str
    type: TokenType
    jti: str
    iat: datetime
    exp: datetime
    amr: list[str] = field(default_factory=list)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def new_kid() -> str:
    return f"{datetime.now(UTC):%Y%m%d}-{uuid.uuid4().hex[:8]}"


def generate_private_key_pem() -> bytes:
    return Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


class KeyRing:
    def __init__(self, keys: dict[str, Ed25519PrivateKey], active_kid: str) -> None:
        if active_kid not in keys:
            raise ValueError(f"Active JWT kid {active_kid!r} not present in key ring")
        self._keys = dict(keys)
        self._active_kid = active_kid

    @property
    def active_kid(self) -> str:
        return self._active_kid

    @property
    def kids(self) -> list[str]:
        return sorted(self._keys)

    @classmethod
    def from_directory(
        cls, directory: Path, *, active_kid: str | None = None, auto_generate: bool = False
    ) -> KeyRing:
        directory.mkdir(parents=True, exist_ok=True)
        files = sorted(directory.glob("*.pem"))
        if not files:
            if not auto_generate:
                raise RuntimeError(f"No JWT signing keys found in {directory}")
            path = directory / f"{new_kid()}.pem"
            path.write_bytes(generate_private_key_pem())
            path.chmod(0o600)
            files = [path]
        keys: dict[str, Ed25519PrivateKey] = {}
        for path in files:
            key = serialization.load_pem_private_key(path.read_bytes(), password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise TypeError(f"{path.name} is not an Ed25519 private key")
            keys[path.stem] = key
        # Default to the lexicographically newest kid (kids are date-prefixed).
        return cls(keys, active_kid or max(keys))

    def _public(self, kid: str) -> Ed25519PublicKey:
        return self._keys[kid].public_key()

    def jwks(self) -> dict[str, list[dict[str, str]]]:
        out: list[dict[str, str]] = []
        for kid in self.kids:
            raw = self._public(kid).public_bytes(
                encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
            )
            out.append(
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": _b64url(raw),
                    "kid": kid,
                    "alg": ALGORITHM,
                    "use": "sig",
                }
            )
        return {"keys": out}

    def sign(self, claims: dict[str, Any]) -> str:
        return jwt.encode(
            claims,
            self._keys[self._active_kid],
            algorithm=ALGORITHM,
            headers={"kid": self._active_kid, "typ": "JWT"},
        )

    def verify(self, token: str, *, audience: str, issuer: str) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise InvalidToken() from exc
        kid = header.get("kid")
        # Pin the algorithm: never trust the token's own ``alg`` header (alg=none / HS confusion).
        if header.get("alg") != ALGORITHM or not isinstance(kid, str) or kid not in self._keys:
            raise InvalidToken()
        try:
            return jwt.decode(
                token,
                self._public(kid),
                algorithms=[ALGORITHM],
                audience=audience,
                issuer=issuer,
                options={"require": ["exp", "iat", "nbf", "sub", "jti", "aud", "iss"]},
            )
        except jwt.PyJWTError as exc:
            raise InvalidToken() from exc


class TokenService:
    def __init__(self, keyring: KeyRing, *, issuer: str, audience: str) -> None:
        self.keyring = keyring
        self.issuer = issuer
        self.audience = audience

    def issue(
        self, subject: str, token_type: TokenType, ttl_seconds: int, *, amr: list[str] | None = None
    ) -> tuple[str, TokenClaims]:
        # Truncate to whole seconds: JWT NumericDate has second precision.
        now = datetime.now(UTC).replace(microsecond=0)
        claims = TokenClaims(
            sub=subject,
            type=token_type,
            jti=uuid.uuid4().hex,
            iat=now,
            exp=now + timedelta(seconds=ttl_seconds),
            amr=amr or ["pwd"],
        )
        payload = {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": subject,
            "typ": token_type.value,
            "jti": claims.jti,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int(claims.exp.timestamp()),
            "amr": claims.amr,
        }
        return self.keyring.sign(payload), claims

    def decode(self, token: str, expected_type: TokenType) -> TokenClaims:
        data = self.keyring.verify(token, audience=self.audience, issuer=self.issuer)
        if data.get("typ") != expected_type.value:
            raise InvalidToken()
        return TokenClaims(
            sub=str(data["sub"]),
            type=expected_type,
            jti=str(data["jti"]),
            iat=datetime.fromtimestamp(int(data["iat"]), UTC),
            exp=datetime.fromtimestamp(int(data["exp"]), UTC),
            amr=[str(a) for a in data.get("amr", [])],
        )
