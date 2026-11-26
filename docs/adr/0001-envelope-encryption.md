# ADR 0001: Envelope encryption with per-version data keys

- Status: Accepted
- Date: 2026-11-26

## Context

Secrets must be encrypted at rest so that a database dump, a leaked backup or a
read-only SQL injection does not expose plaintext. The master key must be
rotatable without downtime, and we want to move to a managed KMS later without a
data migration.

## Decision

* Every **secret version** is encrypted with a fresh random 256-bit **data
  encryption key (DEK)** using **AES-256-GCM** (96-bit random nonce).
* The DEK is wrapped (AES-256-GCM) by a **key encryption key (KEK)** held by a
  `KeyProvider`. We store `ciphertext`, `wrapped_dek` and `master_key_id` per row.
* The **associated data** is `vaultgate:secret:<secret_id>:v<version>` for both
  the payload and the DEK wrap, binding the ciphertext to its row.
* The only provider shipped today is `LocalKeyProvider` (JSON key file mounted
  from a secret manager). The `KeyProvider` protocol is three methods
  (`active_key_id`, `wrap`, `unwrap`) so a KMS implementation is a new class.

## Consequences

* KEK rotation = add a key, make it active, run `vaultgate rewrap-secrets`.
  Only 32-byte DEKs are re-encrypted; bulk data is never touched.
* Copying ciphertext between rows (attacker with DB write access) fails GCM
  authentication instead of decrypting the wrong secret; the API fails closed
  with a 500 and an `secret.decrypt_failed` audit event (tested).
* Random 96-bit nonces are safe here because each DEK encrypts exactly one
  message; the KEK wraps one DEK per version, far below the ~2^32 message bound.
* The KEK still lives in application memory with the local provider. A KMS/HSM
  provider (roadmap) removes that: the API would only ever see DEKs.
