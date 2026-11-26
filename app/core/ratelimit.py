"""Token-bucket rate limiting with pluggable backends.

A bucket holds up to ``capacity`` tokens and refills continuously at
``refill_per_sec``. Each request takes ``cost`` tokens; if not enough are
available the request is rejected with the number of seconds until it would
succeed. Token buckets allow short bursts while bounding the sustained rate,
which suits API clients far better than fixed windows (no thundering herd at
window boundaries).

* :class:`InMemoryRateLimiter` - single process; used in dev/tests.
* :class:`RedisRateLimiter` - atomic Lua script; shared across replicas.
"""

from __future__ import annotations

import asyncio
import math
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from redis.asyncio import Redis


@dataclass(frozen=True, slots=True)
class RateLimitResult:
    allowed: bool
    limit: int
    remaining: int
    retry_after: float  # seconds; 0 when allowed


class RateLimiter(Protocol):
    async def hit(
        self, key: str, capacity: int, refill_per_sec: float, cost: int = 1
    ) -> RateLimitResult: ...


def _compute(
    tokens: float, last: float, now: float, capacity: int, rate: float, cost: int
) -> tuple[float, RateLimitResult]:
    tokens = min(float(capacity), tokens + max(0.0, now - last) * rate)
    if tokens >= cost:
        tokens -= cost
        return tokens, RateLimitResult(True, capacity, math.floor(tokens), 0.0)
    return tokens, RateLimitResult(False, capacity, math.floor(tokens), (cost - tokens) / rate)


class InMemoryRateLimiter:
    """Process-local limiter with LRU eviction to bound memory under key-spraying."""

    def __init__(
        self, max_keys: int = 100_000, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()
        self._max_keys = max_keys
        self._lock = asyncio.Lock()
        self._now = clock

    async def hit(
        self, key: str, capacity: int, refill_per_sec: float, cost: int = 1
    ) -> RateLimitResult:
        async with self._lock:
            now = self._now()
            tokens, last = self._buckets.pop(key, (float(capacity), now))
            tokens, result = _compute(tokens, last, now, capacity, refill_per_sec, cost)
            self._buckets[key] = (tokens, now)
            while len(self._buckets) > self._max_keys:
                self._buckets.popitem(last=False)
            return result


_LUA_TOKEN_BUCKET = """
local key      = KEYS[1]
local capacity = tonumber(ARGV[1])
local rate     = tonumber(ARGV[2])
local now      = tonumber(ARGV[3])
local cost     = tonumber(ARGV[4])
local state    = redis.call('HMGET', key, 'tokens', 'ts')
local tokens   = tonumber(state[1])
local ts       = tonumber(state[2])
if tokens == nil then
  tokens = capacity
  ts = now
end
local delta = math.max(0, now - ts)
tokens = math.min(capacity, tokens + delta * rate)
local allowed = 0
if tokens >= cost then
  tokens = tokens - cost
  allowed = 1
end
redis.call('HSET', key, 'tokens', tostring(tokens), 'ts', tostring(now))
redis.call('PEXPIRE', key, math.ceil((capacity / rate) * 1000) + 1000)
return {allowed, tostring(tokens)}
"""  # noqa: S105 - Lua source, not a credential


class RedisRateLimiter:
    """Distributed limiter: the whole read-modify-write runs atomically in Redis."""

    def __init__(self, redis: Redis, prefix: str = "vg:rl:") -> None:
        self._redis = redis
        self._prefix = prefix
        self._script = redis.register_script(_LUA_TOKEN_BUCKET)

    async def hit(
        self, key: str, capacity: int, refill_per_sec: float, cost: int = 1
    ) -> RateLimitResult:
        # Use wall-clock time: monotonic clocks are not comparable across replicas.
        now = time.time()
        raw = await self._script(
            keys=[self._prefix + key], args=[capacity, refill_per_sec, now, cost]
        )
        allowed, tokens_raw = int(raw[0]), float(raw[1])
        if allowed:
            return RateLimitResult(True, capacity, math.floor(tokens_raw), 0.0)
        return RateLimitResult(
            False, capacity, math.floor(tokens_raw), (cost - tokens_raw) / refill_per_sec
        )
