from __future__ import annotations

import base64
import dataclasses
import json
from pathlib import Path

import pytest

from app.core.crypto import (
    DecryptionError,
    EncryptedPayload,
    EnvelopeCipher,
    KeyProvider,
    LocalKeyProvider,
    UnknownKeyError,
)

AAD = b"vaultgate:secret:abc:v1"


@pytest.fixture
def cipher() -> EnvelopeCipher:
    return EnvelopeCipher(LocalKeyProvider.generate())


def test_roundtrip(cipher: EnvelopeCipher) -> None:
    payload = cipher.encrypt(b"hunter2", AAD)
    assert b"hunter2" not in payload.ciphertext
    assert cipher.decrypt(payload, AAD) == b"hunter2"


def test_each_encryption_uses_fresh_dek_and_nonce(cipher: EnvelopeCipher) -> None:
    a = cipher.encrypt(b"same", AAD)
    b = cipher.encrypt(b"same", AAD)
    assert a.ciphertext != b.ciphertext
    assert a.wrapped_dek != b.wrapped_dek


def test_wrong_aad_fails(cipher: EnvelopeCipher) -> None:
    payload = cipher.encrypt(b"data", AAD)
    with pytest.raises(DecryptionError):
        cipher.decrypt(payload, b"vaultgate:secret:abc:v2")


@pytest.mark.parametrize("field", ["ciphertext", "wrapped_dek"])
def test_bit_flip_detected(cipher: EnvelopeCipher, field: str) -> None:
    payload = cipher.encrypt(b"data", AAD)
    raw = bytearray(getattr(payload, field))
    raw[-1] ^= 0x01
    if field == "ciphertext":
        tampered = dataclasses.replace(payload, ciphertext=bytes(raw))
    else:
        tampered = dataclasses.replace(payload, wrapped_dek=bytes(raw))
    with pytest.raises(DecryptionError):
        cipher.decrypt(tampered, AAD)


def test_truncated_ciphertext(cipher: EnvelopeCipher) -> None:
    payload = cipher.encrypt(b"data", AAD)
    with pytest.raises(DecryptionError, match="too short"):
        cipher.decrypt(EncryptedPayload(b"short", payload.wrapped_dek, payload.key_id), AAD)


def test_other_master_key_cannot_decrypt(cipher: EnvelopeCipher) -> None:
    payload = cipher.encrypt(b"data", AAD)
    other = LocalKeyProvider.generate()
    impostor = LocalKeyProvider({payload.key_id: other._keys[other.active_key_id]}, payload.key_id)
    with pytest.raises(DecryptionError):
        EnvelopeCipher(impostor).decrypt(payload, AAD)


def test_unknown_key_id(cipher: EnvelopeCipher) -> None:
    payload = cipher.encrypt(b"data", AAD)
    with pytest.raises(UnknownKeyError):
        EnvelopeCipher(LocalKeyProvider.generate()).decrypt(payload, AAD)


def test_rotation_and_rewrap() -> None:
    v1 = LocalKeyProvider.generate()
    payload = EnvelopeCipher(v1).encrypt(b"long-lived", AAD)

    v2 = v1.with_new_active_key()
    assert v2.active_key_id != v1.active_key_id
    assert set(v2.key_ids) == {v1.active_key_id, v2.active_key_id}
    c2 = EnvelopeCipher(v2)
    assert c2.decrypt(payload, AAD) == b"long-lived"  # old data still readable

    rewrapped = c2.rewrap(payload, AAD)
    assert rewrapped.key_id == v2.active_key_id
    assert rewrapped.ciphertext == payload.ciphertext  # bulk data untouched
    assert c2.rewrap(rewrapped, AAD) is rewrapped  # no-op when already current

    only_v2 = LocalKeyProvider({v2.active_key_id: v2._keys[v2.active_key_id]}, v2.active_key_id)
    assert EnvelopeCipher(only_v2).decrypt(rewrapped, AAD) == b"long-lived"
    with pytest.raises(UnknownKeyError):
        EnvelopeCipher(only_v2).decrypt(payload, AAD)


def test_blob_roundtrip(cipher: EnvelopeCipher) -> None:
    payload = cipher.encrypt(b"totp-seed", AAD)
    blob = payload.to_blob()
    assert EncryptedPayload.from_blob(blob) == payload
    with pytest.raises(DecryptionError):
        EncryptedPayload.from_blob(b"\x09garbage")


def test_provider_persistence(tmp_path: Path) -> None:
    path = tmp_path / "keys" / "mk.json"
    with pytest.raises(RuntimeError):
        LocalKeyProvider.load(path)
    created = LocalKeyProvider.load(path, auto_generate=True)
    loaded = LocalKeyProvider.load(path)
    assert loaded.active_key_id == created.active_key_id
    doc = json.loads(path.read_text())
    assert len(base64.b64decode(doc["keys"][doc["active"]])) == 32
    assert isinstance(loaded, KeyProvider)


def test_provider_validation() -> None:
    with pytest.raises(ValueError, match="missing"):
        LocalKeyProvider({"a": b"\0" * 32}, "b")
    with pytest.raises(ValueError, match="32 bytes"):
        LocalKeyProvider({"a": b"\0" * 16}, "a")
