"""Envelope encryption for secrets at rest.

::

    plaintext --AES-256-GCM(DEK, nonce, AAD)--> ciphertext        (stored)
    DEK       --KeyProvider.wrap(KEK, AAD)----> wrapped_dek       (stored)
    KEK       lives only in the key provider (local file / KMS / HSM)

* Each secret *version* gets a fresh random 256-bit data-encryption key (DEK).
* The DEK is wrapped by a key-encryption key (KEK, "master key") held by a
  :class:`KeyProvider`. Only the provider ever sees the KEK, so swapping the
  local file provider for AWS KMS / GCP KMS / Vault Transit is a new class, not
  a data migration.
* The associated data (AAD) binds each ciphertext to its database row
  (``secret_id`` + ``version``). Copying ciphertext between rows - a classic
  "confused deputy" attack by someone with DB write access - fails
  authentication instead of silently decrypting the wrong secret.
* Master-key rotation only re-wraps DEKs (32 bytes each); bulk data is never
  re-encrypted. See ``vaultgate rewrap-secrets`` and ``docs/adr/0001``.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, runtime_checkable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_BYTES = 32
NONCE_BYTES = 12
_BLOB_VERSION = 1


class DecryptionError(Exception):
    """Ciphertext failed authentication (tampered, wrong AAD, or wrong key)."""


class UnknownKeyError(DecryptionError):
    """The payload references a master key the provider does not hold."""


@runtime_checkable
class KeyProvider(Protocol):
    """Abstraction over wherever the key-encryption keys live."""

    @property
    def active_key_id(self) -> str: ...

    def wrap(self, dek: bytes, aad: bytes) -> tuple[str, bytes]:
        """Encrypt ``dek`` under the active KEK; returns ``(key_id, wrapped)``."""
        ...

    def unwrap(self, key_id: str, wrapped: bytes, aad: bytes) -> bytes:
        """Decrypt a DEK previously produced by :meth:`wrap`."""
        ...


def _seal(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(NONCE_BYTES)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def _open(key: bytes, blob: bytes, aad: bytes) -> bytes:
    if len(blob) < NONCE_BYTES + 16:
        raise DecryptionError("ciphertext too short")
    try:
        return AESGCM(key).decrypt(blob[:NONCE_BYTES], blob[NONCE_BYTES:], aad)
    except InvalidTag as exc:
        raise DecryptionError("authentication failed") from exc


class LocalKeyProvider:
    """KEKs held in a JSON key file - for development and single-node installs.

    File format::

        {"active": "mk-20260101", "keys": {"mk-20260101": "<base64 32 bytes>"}}

    In production mount this file from a secret manager (see k8s/externalsecret.yaml)
    or replace the provider with a KMS-backed implementation.
    """

    def __init__(self, keys: dict[str, bytes], active_key_id: str) -> None:
        if active_key_id not in keys:
            raise ValueError(f"active master key {active_key_id!r} missing from key ring")
        for kid, key in keys.items():
            if len(key) != KEY_BYTES:
                raise ValueError(f"master key {kid!r} must be {KEY_BYTES} bytes")
        self._keys = dict(keys)
        self._active = active_key_id

    @property
    def active_key_id(self) -> str:
        return self._active

    @property
    def key_ids(self) -> list[str]:
        return sorted(self._keys)

    def wrap(self, dek: bytes, aad: bytes) -> tuple[str, bytes]:
        return self._active, _seal(self._keys[self._active], dek, b"kek|" + aad)

    def unwrap(self, key_id: str, wrapped: bytes, aad: bytes) -> bytes:
        key = self._keys.get(key_id)
        if key is None:
            raise UnknownKeyError(f"master key {key_id!r} is not loaded")
        return _open(key, wrapped, b"kek|" + aad)

    # ---------------------------------------------------------------- persistence
    @staticmethod
    def new_key_id() -> str:
        return f"mk-{datetime.now(UTC):%Y%m%d}-{secrets.token_hex(3)}"

    def to_json(self) -> str:
        return json.dumps(
            {
                "active": self._active,
                "keys": {k: base64.b64encode(v).decode() for k, v in sorted(self._keys.items())},
            },
            indent=2,
        )

    @classmethod
    def from_json(cls, raw: str) -> LocalKeyProvider:
        data = json.loads(raw)
        keys = {str(k): base64.b64decode(v) for k, v in data["keys"].items()}
        return cls(keys, str(data["active"]))

    @classmethod
    def generate(cls) -> LocalKeyProvider:
        kid = cls.new_key_id()
        return cls({kid: AESGCM.generate_key(bit_length=256)}, kid)

    def with_new_active_key(self) -> LocalKeyProvider:
        """Return a provider with a freshly generated active key (old keys retained)."""
        kid = self.new_key_id()
        while kid in self._keys:  # pragma: no cover - 24-bit suffix collision
            kid = self.new_key_id()
        return LocalKeyProvider({**self._keys, kid: AESGCM.generate_key(bit_length=256)}, kid)

    @classmethod
    def load(cls, path: Path, *, auto_generate: bool = False) -> LocalKeyProvider:
        if not path.exists():
            if not auto_generate:
                raise RuntimeError(f"master key file {path} not found")
            provider = cls.generate()
            provider.save(path)
            return provider
        return cls.from_json(path.read_text(encoding="utf-8"))

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(self.to_json(), encoding="utf-8")
        tmp.chmod(0o600)
        tmp.replace(path)


@dataclass(frozen=True, slots=True)
class EncryptedPayload:
    ciphertext: bytes
    wrapped_dek: bytes
    key_id: str

    def to_blob(self) -> bytes:
        """Self-describing single-column encoding (used for small fields like TOTP seeds)."""
        kid = self.key_id.encode()
        return (
            bytes([_BLOB_VERSION, len(kid)])
            + kid
            + len(self.wrapped_dek).to_bytes(2, "big")
            + self.wrapped_dek
            + self.ciphertext
        )

    @classmethod
    def from_blob(cls, blob: bytes) -> EncryptedPayload:
        if not blob or blob[0] != _BLOB_VERSION:
            raise DecryptionError("unsupported blob version")
        kid_len = blob[1]
        kid = blob[2 : 2 + kid_len].decode()
        off = 2 + kid_len
        dek_len = int.from_bytes(blob[off : off + 2], "big")
        off += 2
        return cls(
            ciphertext=blob[off + dek_len :], wrapped_dek=blob[off : off + dek_len], key_id=kid
        )


class EnvelopeCipher:
    def __init__(self, provider: KeyProvider) -> None:
        self.provider = provider

    def encrypt(self, plaintext: bytes, aad: bytes) -> EncryptedPayload:
        dek = AESGCM.generate_key(bit_length=256)
        ciphertext = _seal(dek, plaintext, aad)
        key_id, wrapped = self.provider.wrap(dek, aad)
        return EncryptedPayload(ciphertext=ciphertext, wrapped_dek=wrapped, key_id=key_id)

    def decrypt(self, payload: EncryptedPayload, aad: bytes) -> bytes:
        dek = self.provider.unwrap(payload.key_id, payload.wrapped_dek, aad)
        return _open(dek, payload.ciphertext, aad)

    def rewrap(self, payload: EncryptedPayload, aad: bytes) -> EncryptedPayload:
        """Re-wrap the DEK under the provider's active key without touching the data."""
        if payload.key_id == self.provider.active_key_id:
            return payload
        dek = self.provider.unwrap(payload.key_id, payload.wrapped_dek, aad)
        key_id, wrapped = self.provider.wrap(dek, aad)
        return EncryptedPayload(ciphertext=payload.ciphertext, wrapped_dek=wrapped, key_id=key_id)
