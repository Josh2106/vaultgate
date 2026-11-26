"""Rate-limiter and idempotency backends (in-memory and Redis via fakeredis+Lua)."""

from __future__ import annotations

from collections.abc import AsyncIterator

import fakeredis
import pytest

from app.core.idempotency import (
    IdempotencyStore,
    InMemoryIdempotencyStore,
    RedisIdempotencyStore,
    ReserveOutcome,
    StoredResponse,
)
from app.core.ratelimit import InMemoryRateLimiter, RateLimiter, RedisRateLimiter

pytestmark = pytest.mark.asyncio


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


async def test_token_bucket_burst_then_refill() -> None:
    clock = FakeClock()
    limiter = InMemoryRateLimiter(clock=clock)
    results = [await limiter.hit("k", capacity=3, refill_per_sec=1.0) for _ in range(4)]
    assert [r.allowed for r in results] == [True, True, True, False]
    assert results[0].remaining == 2
    assert results[3].retry_after == pytest.approx(1.0)
    clock.now += 1.0
    assert (await limiter.hit("k", 3, 1.0)).allowed
    assert not (await limiter.hit("k", 3, 1.0)).allowed
    clock.now += 100  # refill is capped at capacity
    assert (await limiter.hit("k", 3, 1.0)).remaining == 2


async def test_buckets_are_independent_and_bounded() -> None:
    limiter = InMemoryRateLimiter(max_keys=2, clock=FakeClock())
    assert (await limiter.hit("a", 1, 0.001)).allowed
    assert not (await limiter.hit("a", 1, 0.001)).allowed
    assert (await limiter.hit("b", 1, 0.001)).allowed
    await limiter.hit("c", 1, 0.001)  # evicts the least-recently-used bucket ("a")
    assert len(limiter._buckets) == 2
    assert "a" not in limiter._buckets


async def test_cost_greater_than_one() -> None:
    limiter = InMemoryRateLimiter(clock=FakeClock())
    assert (await limiter.hit("k", 10, 1.0, cost=7)).remaining == 3
    r = await limiter.hit("k", 10, 1.0, cost=7)
    assert not r.allowed and r.retry_after == pytest.approx(4.0)


@pytest.fixture
async def redis() -> AsyncIterator[fakeredis.FakeAsyncRedis]:
    r = fakeredis.FakeAsyncRedis()
    yield r
    await r.aclose()


async def test_redis_token_bucket(redis: fakeredis.FakeAsyncRedis) -> None:
    limiter: RateLimiter = RedisRateLimiter(redis)
    results = [await limiter.hit("ip:1", capacity=2, refill_per_sec=0.001) for _ in range(3)]
    assert [r.allowed for r in results] == [True, True, False]
    assert results[2].retry_after > 0
    assert await redis.pttl("vg:rl:ip:1") > 0  # keys expire; no unbounded growth


@pytest.fixture(params=["memory", "redis"])
async def store(
    request: pytest.FixtureRequest, redis: fakeredis.FakeAsyncRedis
) -> IdempotencyStore:
    if request.param == "memory":
        return InMemoryIdempotencyStore()
    return RedisIdempotencyStore(redis)


async def test_idempotency_store_lifecycle(store: IdempotencyStore) -> None:
    assert (await store.reserve("k", "fp1", 60)).outcome is ReserveOutcome.RESERVED
    assert (await store.reserve("k", "fp1", 60)).outcome is ReserveOutcome.IN_PROGRESS
    assert (await store.reserve("k", "fp2", 60)).outcome is ReserveOutcome.MISMATCH
    resp = StoredResponse(201, [("content-type", "application/json")], b'{"ok":true}')
    await store.complete("k", "fp1", resp, 60)
    done = await store.reserve("k", "fp1", 60)
    assert done.outcome is ReserveOutcome.COMPLETED
    assert done.response is not None and done.response.body == b'{"ok":true}'
    assert done.response.headers == [("content-type", "application/json")]
    await store.release("k")
    assert (await store.reserve("k", "fp2", 60)).outcome is ReserveOutcome.RESERVED


async def test_memory_store_expiry() -> None:
    store = InMemoryIdempotencyStore()
    await store.reserve("k", "fp", ttl=-1)  # already expired
    assert (await store.reserve("k", "other", 60)).outcome is ReserveOutcome.RESERVED
