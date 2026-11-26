# ADR 0004: EdDSA (Ed25519) JWTs with a `kid` key ring, not HS256

- Status: Accepted
- Date: 2026-11-26

## Context

HS256 uses one shared secret to both sign and verify. Every service that needs
to verify a token can also mint one, the secret tends to be copied into many
places, and rotating it is a flag day. Classic JWT pitfalls (`alg=none`,
RS/HS algorithm confusion) also need explicit defence.

## Decision

* Sign access and MFA-challenge tokens with **EdDSA / Ed25519** (small keys,
  fast, deterministic signatures, no parameter choices to get wrong). RS256
  would have been equally acceptable; Ed25519 was chosen for key size and speed.
* Keys live in a **key ring** directory of `<kid>.pem` files (a Kubernetes
  Secret volume). One kid is active for signing; all present kids verify.
* Every token has a `kid` header. Verification **pins the algorithm** to
  `EdDSA`, rejects unknown kids, and requires `exp, iat, nbf, sub, jti, aud, iss`.
  A `typ` claim separates access tokens from MFA tokens (no type confusion).
* Public keys are served at `/.well-known/jwks.json`.

## Rotation procedure

1. `vaultgate generate-jwt-key` and add the PEM to the secret (verifiers learn it).
2. Set `VG_JWT_ACTIVE_KID` (or rely on newest-kid default) and roll the deployment.
3. After one access-token TTL (15 min), remove the old PEM.

## Consequences

* Other services can verify tokens with public keys only.
* Overlap windows make rotation zero-downtime (covered by an integration test
  that rotates, verifies an old token, retires the old key and sees it rejected).
