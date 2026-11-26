"""Storage for ``Idempotency-Key`` request de-duplication.

Semantics follow draft-ietf-httpapi-idempotency-key-header:

* First request with a key reserves it (state ``pending``) and executes.
* A concurrent retry while the first is still running gets ``409 Conflict``.
* A retry after completion replays the stored response byte-for-byte.
* Re-using a key with a *different* request body is a client bug -> ``422``.
"""

from __future__ import annotations

import asyncio
import base64
import json
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol

from redis.asyncio import Redis


class ReserveOutcome(StrEnum):
    RESERVED = "reserved"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    MISMATCH = "mismatch"


@dataclass(slots=True)
class StoredResponse:
    status: int
    headers: list[tuple[str, str]]
    body: bytes

    def dumps(self) -> dict[str, object]:
        return {
            "status": self.status,
            "headers": self.headers,
            "body": base64.b64encode(self.body).decode(),
        }

    @classmethod
    def loads(cls, data: dict[str, object]) -> StoredResponse:
        headers = data["headers"]
        assert isinstance(headers, list)  # noqa: S101 - internal format
        return cls(
            status=int(str(data["status"])),
            headers=[(str(k), str(v)) for k, v in headers],
            body=base64.b64decode(str(data["body"])),
        )


@dataclass(slots=True)
class Reservation:
    outcome: ReserveOutcome
    response: StoredResponse | None = None


class IdempotencyStore(Protocol):
    async def reserve(self, key: str, fingerprint: str, ttl: int) -> Reservation: ...
    async def complete(
        self, key: str, fingerprint: str, response: StoredResponse, ttl: int
    ) -> None: ...
    async def release(self, key: str) -> None: ...


def _decide(record: dict[str, object], fingerprint: str) -> Reservation:
    if record.get("fp") != fingerprint:
        return Reservation(ReserveOutcome.MISMATCH)
    if record.get("state") == "done":
        resp = record.get("response")
        assert isinstance(resp, dict)  # noqa: S101
        return Reservation(ReserveOutcome.COMPLETED, StoredResponse.loads(resp))
    return Reservation(ReserveOutcome.IN_PROGRESS)


@dataclass
class InMemoryIdempotencyStore:
    _data: dict[str, tuple[float, dict[str, object]]] = field(default_factory=dict)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def _get(self, key: str) -> dict[str, object] | None:
        item = self._data.get(key)
        if item is None:
            return None
        expires, record = item
        if expires < time.monotonic():
            del self._data[key]
            return None
        return record

    async def reserve(self, key: str, fingerprint: str, ttl: int) -> Reservation:
        async with self._lock:
            record = self._get(key)
            if record is not None:
                return _decide(record, fingerprint)
            self._data[key] = (time.monotonic() + ttl, {"state": "pending", "fp": fingerprint})
            return Reservation(ReserveOutcome.RESERVED)

    async def complete(
        self, key: str, fingerprint: str, response: StoredResponse, ttl: int
    ) -> None:
        async with self._lock:
            self._data[key] = (
                time.monotonic() + ttl,
                {"state": "done", "fp": fingerprint, "response": response.dumps()},
            )

    async def release(self, key: str) -> None:
        async with self._lock:
            self._data.pop(key, None)


class RedisIdempotencyStore:
    def __init__(self, redis: Redis, prefix: str = "vg:idem:") -> None:
        self._redis = redis
        self._prefix = prefix

    async def reserve(self, key: str, fingerprint: str, ttl: int) -> Reservation:
        rkey = self._prefix + key
        pending = json.dumps({"state": "pending", "fp": fingerprint})
        # SET NX is the atomic "claim" - exactly one concurrent request wins.
        if await self._redis.set(rkey, pending, nx=True, ex=ttl):
            return Reservation(ReserveOutcome.RESERVED)
        raw = await self._redis.get(rkey)
        if raw is None:  # expired between SET and GET; treat as in-progress, client retries
            return Reservation(ReserveOutcome.IN_PROGRESS)
        return _decide(json.loads(raw), fingerprint)

    async def complete(
        self, key: str, fingerprint: str, response: StoredResponse, ttl: int
    ) -> None:
        record = {"state": "done", "fp": fingerprint, "response": response.dumps()}
        await self._redis.set(self._prefix + key, json.dumps(record), ex=ttl)

    async def release(self, key: str) -> None:
        await self._redis.delete(self._prefix + key)
