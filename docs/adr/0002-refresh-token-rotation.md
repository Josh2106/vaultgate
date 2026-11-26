# ADR 0002: Refresh-token rotation with reuse detection

- Status: Accepted
- Date: 2026-11-26

## Context

Access tokens are short-lived JWTs (15 min) so they cannot be revoked
individually at low cost. Sessions therefore depend on a long-lived refresh
token, which is the most valuable credential a client holds. If it is stolen
(XSS, malware, leaked logs) a plain long-lived token gives the attacker access
for its whole lifetime.

## Decision

* Refresh tokens are opaque 256-bit random strings (`vgr_...`), stored only as
  SHA-256 hashes. Each login creates a **family** (`family_id`).
* `/auth/refresh` **rotates**: the presented token is marked `used_at` with an
  atomic compare-and-set (`UPDATE ... WHERE used_at IS NULL`) and a child token
  in the same family is issued.
* Presenting a token that is already used or revoked is treated as **theft**:
  every token in the family is revoked, an `auth.refresh_reuse_detected` audit
  event is written and the `vaultgate_auth_refresh_reuse_total` metric increments.
* Logout revokes the family; logout-all and password change revoke every family
  and set `tokens_valid_after`, which also invalidates outstanding access tokens.

## Consequences

* Whichever party (legitimate client or attacker) uses a stolen token second
  triggers revocation of both, bounding the attack window to one refresh cycle.
* Strict rotation has no grace period, so two browser tabs racing to refresh
  will log the user out. A short reuse grace window is a known trade-off we
  have deliberately not taken; clients should serialise refreshes.
* `tokens_valid_after` has 1-second resolution (JWT `iat` is in seconds).
