"""Password hashing, password policy and opaque-token primitives.

Design notes
------------
* Passwords are hashed with **Argon2id** (memory-hard; OWASP's first choice).
  Parameters are configurable so tests can run fast while production uses
  64 MiB / t=3 / p=4.
* For unknown users we still run a full Argon2 verification against a dummy
  hash so response timing does not reveal whether an account exists.
* Opaque tokens (refresh tokens, API keys, email-verification tokens, recovery
  codes) are 256-bit random values. Because they have full entropy they are
  stored as a SHA-256 digest - a slow KDF adds nothing against brute force of a
  256-bit secret but would make every authenticated request expensive.
* All secret comparisons go through :func:`constant_time_equals`.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import string
from dataclasses import dataclass

from argon2 import PasswordHasher as _Argon2
from argon2 import Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.core.config import Settings

# A short list of the most common passwords that satisfy naive length rules.
# Real deployments should plug in a k-anonymity breach check (HIBP); see roadmap.
_COMMON_PASSWORDS = frozenset(
    {
        "password1234",
        "passwordpassword",
        "123456789012",
        "qwertyuiopasdf",
        "iloveyou1234",
        "letmein12345",
        "administrator",
        "welcome12345",
        "changeme1234",
        "correcthorsebatterystaple",
    }
)


class PasswordHasher:
    """Thin wrapper around argon2-cffi that also handles rehash-on-login."""

    def __init__(self, settings: Settings) -> None:
        self._hasher = _Argon2(
            time_cost=settings.argon2_time_cost,
            memory_cost=settings.argon2_memory_cost_kib,
            parallelism=settings.argon2_parallelism,
            hash_len=32,
            salt_len=16,
            type=Type.ID,
        )
        self._dummy_hash = self._hasher.hash(secrets.token_urlsafe(32))

    def hash(self, password: str) -> str:
        return self._hasher.hash(password)

    def verify(self, password_hash: str | None, password: str) -> bool:
        """Verify ``password``; when ``password_hash`` is ``None`` burn equivalent CPU."""
        target = password_hash or self._dummy_hash
        try:
            ok = self._hasher.verify(target, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False
        return ok and password_hash is not None

    def needs_rehash(self, password_hash: str) -> bool:
        return self._hasher.check_needs_rehash(password_hash)


@dataclass(frozen=True, slots=True)
class PasswordPolicy:
    """NIST SP 800-63B inspired policy: length over composition, plus a blocklist."""

    min_length: int = 12
    max_length: int = 128

    def violations(self, password: str, *, email: str | None = None) -> list[str]:
        problems: list[str] = []
        if len(password) < self.min_length:
            problems.append(f"must be at least {self.min_length} characters")
        if len(password) > self.max_length:
            problems.append(f"must be at most {self.max_length} characters")
        lowered = password.lower()
        if lowered in _COMMON_PASSWORDS:
            problems.append("is too common")
        if len(set(password)) < 4:
            problems.append("must contain at least 4 distinct characters")
        if email:
            local = email.split("@", 1)[0].lower()
            if len(local) >= 4 and local in lowered:
                problems.append("must not contain your email address")
        classes = sum(
            any(c in charset for c in password)
            for charset in (
                string.ascii_lowercase,
                string.ascii_uppercase,
                string.digits,
                string.punctuation + " ",
            )
        )
        if classes < 2:
            problems.append("must mix at least two of: lowercase, uppercase, digits, symbols")
        return problems


def sha256_hex(value: str | bytes) -> str:
    data = value.encode() if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


def constant_time_equals(a: str | bytes, b: str | bytes) -> bool:
    a_b = a.encode() if isinstance(a, str) else a
    b_b = b.encode() if isinstance(b, str) else b
    return hmac.compare_digest(a_b, b_b)


def generate_token(nbytes: int = 32) -> str:
    """URL-safe random token with ``nbytes`` of entropy."""
    return secrets.token_urlsafe(nbytes)


_B32 = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # Crockford-ish, no ambiguous chars


def generate_recovery_code() -> str:
    """Human-friendly ``XXXXX-XXXXX`` code (~50 bits)."""
    raw = "".join(secrets.choice(_B32) for _ in range(10))
    return f"{raw[:5]}-{raw[5:]}"


def normalize_recovery_code(code: str) -> str:
    return code.strip().upper().replace(" ", "")
