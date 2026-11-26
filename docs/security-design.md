# Security design

## Assets

| Asset | Where it lives | Protection |
|---|---|---|
| Secret values | `secret_versions.ciphertext` | AES-256-GCM, per-version DEK, AAD-bound to row |
| Data keys (DEKs) | `secret_versions.wrapped_dek` | Wrapped by KEK (AES-256-GCM) |
| Master keys (KEKs) | Key file from secret manager (KMS on roadmap) | Never in DB, never in image |
| JWT signing keys | `<kid>.pem` volume | Ed25519, rotated via `kid` |
| Passwords | `users.password_hash` | Argon2id (64 MiB, t=3, p=4) |
| Refresh tokens, API keys, email tokens, recovery codes | DB | SHA-256 of 256-bit (recovery: ~50-bit, single-use, rate-limited) random values |
| TOTP seeds | `users.totp_secret_enc` | Envelope-encrypted like secrets |
| Audit trail | `audit_events` | Append-only triggers + SHA-256 hash chain |

## Cryptography

* **AEAD**: AES-256-GCM from `cryptography` (OpenSSL). 96-bit random nonces;
  each DEK encrypts exactly one plaintext.
* **AAD**: `vaultgate:secret:<secret_id>:v<n>` / `vaultgate:totp:<user_id>`. The
  KEK wrap uses `kek|<aad>` so a wrapped DEK cannot be confused with payload data.
* **KDF for passwords**: Argon2id with rehash-on-login when parameters change.
  Unknown users still incur a full Argon2 verification (timing-safe enumeration
  resistance).
* **Token hashing**: SHA-256 is sufficient for 256-bit random tokens (brute force
  is infeasible); a slow KDF would only add per-request latency.
* **Comparisons**: `hmac.compare_digest` everywhere a secret is compared.
* **Signatures**: Ed25519 JWTs, algorithm pinned, `kid` required, JWKS published.
* **Randomness**: `secrets` / `os.urandom` only.

## Threat model (STRIDE)

| # | Threat | STRIDE | Mitigation | Verified by |
|---|---|---|---|---|
| T1 | Credential stuffing / brute force on login | S | Per-IP auth token bucket (10 burst, 1 per 5 s), account lockout after 5 failures, Argon2id cost | `test_rate_limit_auth_bucket`, `test_account_lockout` |
| T2 | Account enumeration via signup/login/lockout | I | Identical responses and timing; signup always 202; lockout returns same 401 | `test_signup_is_enumeration_resistant`, `test_invalid_login_is_generic_problem` |
| T3 | Stolen refresh token | S | Rotation + reuse detection revokes family | `test_refresh_reuse_revokes_whole_family` |
| T4 | Forged JWT (`alg=none`, HS/RS confusion, foreign key) | S/E | Algorithm pinned, kid whitelist, required claims, `typ` separation | `test_forged_headers_rejected`, `test_token_type_confusion_rejected` |
| T5 | Cross-tenant access (BOLA/IDOR) | I/E | Every query scoped by `org_id` from the authorised context; foreign resources return 404 | `test_project_from_other_tenant_is_invisible`, `test_api_key_is_org_bound` |
| T6 | Privilege escalation inside an org | E | Central role matrix; admins cannot mint owners; last-owner guard; API keys cannot hold governance scopes | `test_rbac_matrix` (80 cases), `test_member_management_rules` |
| T7 | Database dump / backup leak | I | Envelope encryption; hashed tokens and keys; KEK outside the DB | `test_plaintext_never_hits_the_database` |
| T8 | Ciphertext swap by DB writer | T | AAD binds ciphertext to row; fails closed + audited | `test_ciphertext_transplant_is_detected` |
| T9 | Audit log tampering | R/T | Append-only triggers + hash chain + CLI verifier | `test_tampering_is_detected` (5 variants) |
| T10 | Mass assignment | T/E | `extra="forbid"` on every request schema | `test_unknown_fields_rejected` |
| T11 | Resource exhaustion (large bodies, key spraying) | D | Body limit (Content-Length and streamed), bounded LRU limiter, per-key buckets | `test_body_size_limit_*`, `test_buckets_are_independent_and_bounded` |
| T12 | Duplicate side effects on retry | T | `Idempotency-Key` with body fingerprint, scoped per principal | `test_idempotent_post_replays` |
| T13 | Information leak via errors / logs | I | Generic 500 problem documents, structlog redaction of secret-like keys | `test_unhandled_errors_are_masked`, `test_log_redaction` |
| T14 | Spoofed client IP for rate limiting | S | `X-Forwarded-For` honoured only for configured trusted hops | `test_client_ip_trusts_only_configured_hops` |
| T15 | Browser-based attacks on API | T/I | Strict CORS allow-list (wildcard rejected), CSP `default-src 'none'`, nosniff, frame-deny, no-store | `test_cors_allows_only_listed_origins`, `test_security_headers` |
| T16 | Insecure production config | E | Settings validator refuses SQLite, auto-generated keys, debug, missing HSTS | `test_production_requires_safe_settings` |

## Known limitations / residual risk

* KEK is held in process memory with `LocalKeyProvider`; Python cannot reliably
  zero memory. A KMS/HSM provider is the intended production path.
* A DB superuser who rewrites the *whole* audit chain including the head row is
  not detected locally; anchoring the head hash externally is on the roadmap.
* No breached-password (HIBP k-anonymity) check yet - only a small blocklist.
* Recovery codes are ~50 bits and hashed with plain SHA-256; acceptable because
  they are single-use, per-user, and the MFA endpoint is rate-limited.
* Strict refresh rotation has no concurrency grace window (see ADR 0002).
