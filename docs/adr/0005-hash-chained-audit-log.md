# ADR 0005: Append-only, hash-chained audit log

- Status: Accepted
- Date: 2026-11-26

## Context

For a secrets manager the audit trail is a security control in its own right:
"who read the production database password, and when?" An attacker who gains
database access will try to erase their tracks.

## Decision

* Every mutating operation (and every secret *value* read) writes an
  `audit_events` row **in the same transaction** as the change.
* Each row stores `prev_hash` and `hash = SHA-256(prev_hash | canonical_json(row))`
  with a contiguous `seq`. A single-row `audit_chain_head` table holds the last
  `seq`/hash; appenders `UPDATE` it first, which takes a row lock (Postgres) or
  the write lock (SQLite) and serialises appends so the chain cannot fork.
* Database triggers reject `UPDATE`/`DELETE` on `audit_events` (both SQLite and
  Postgres variants, installed by the Alembic migration).
* `vaultgate verify-audit-chain` recomputes the chain and exits 2 on the first
  inconsistency (edited row, deleted row, re-linked row, or truncated tail).

## Consequences

* Tampering by someone who can bypass the triggers is **detectable**, not
  prevented. An attacker who rewrites the *entire* chain from the tampered row
  onward, including the head row, defeats local verification. Mitigation
  (roadmap): periodically anchor the head hash somewhere the DB admin cannot
  write (WORM S3 bucket, transparency log, or signed with a KMS key).
* The global chain serialises audit writes - fine for the write volume of a
  secrets manager; sharding chains per org is the path if it ever is not.
