# ADR 0003: Cursor (keyset) pagination

- Status: Accepted
- Date: 2026-11-26

## Context

List endpoints (orgs, members, projects, secrets, API keys, audit events) can
grow without bound. `LIMIT/OFFSET` costs O(offset) on the database and returns
duplicated or skipped rows when rows are inserted between page requests, which
matters for the audit log in particular.

## Decision

* Lists are ordered newest-first by `(created_at, id)`; the audit log by its
  monotonic `seq`.
* The response carries an opaque `next_cursor` (base64url JSON of the last row's
  sort key). The next query seeks with
  `WHERE created_at < :t OR (created_at = :t AND id < :id)`.
* `limit` is clamped to 1-100 (default 50). Malformed cursors return a 422
  problem document, never a 500.

## Consequences

* Constant-time page fetches using existing indexes, stable under concurrent
  writes, and no `COUNT(*)` on hot paths.
* No random access to "page 7" and no total count - acceptable for an API.
* Cursors are not signed: they only carry sort-key values that are bound as SQL
  parameters, and tenant scoping is applied independently of the cursor.
