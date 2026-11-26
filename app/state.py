"""Process-wide resources, built once in the application lifespan."""

from __future__ import annotations

from dataclasses import dataclass, field

from redis.asyncio import Redis
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.core.config import Settings
from app.core.crypto import EnvelopeCipher, LocalKeyProvider
from app.core.email import EmailProvider, build_email_provider
from app.core.idempotency import IdempotencyStore, InMemoryIdempotencyStore, RedisIdempotencyStore
from app.core.metrics import Metrics
from app.core.ratelimit import InMemoryRateLimiter, RateLimiter, RedisRateLimiter
from app.core.security import PasswordHasher, PasswordPolicy
from app.core.tokens import KeyRing, TokenService
from app.db.session import create_engine, create_sessionmaker


@dataclass
class AppState:
    settings: Settings
    engine: AsyncEngine
    sessionmaker: async_sessionmaker[AsyncSession]
    tokens: TokenService
    hasher: PasswordHasher
    policy: PasswordPolicy
    cipher: EnvelopeCipher
    rate_limiter: RateLimiter
    idempotency: IdempotencyStore
    email: EmailProvider
    redis: Redis | None = None
    metrics: Metrics = field(default_factory=Metrics)
    draining: bool = field(default=False)

    @classmethod
    def build(cls, settings: Settings, *, redis: Redis | None = None) -> AppState:
        if redis is None and settings.redis_url:
            redis = Redis.from_url(settings.redis_url, decode_responses=False)
        engine = create_engine(settings)
        keyring = KeyRing.from_directory(
            settings.jwt_keys_dir,
            active_kid=settings.jwt_active_kid,
            auto_generate=settings.jwt_auto_generate,
        )
        provider = LocalKeyProvider.load(
            settings.master_key_file, auto_generate=settings.master_key_auto_generate
        )
        limiter: RateLimiter = RedisRateLimiter(redis) if redis else InMemoryRateLimiter()
        idem: IdempotencyStore = (
            RedisIdempotencyStore(redis) if redis else InMemoryIdempotencyStore()
        )
        return cls(
            settings=settings,
            engine=engine,
            sessionmaker=create_sessionmaker(engine),
            tokens=TokenService(
                keyring, issuer=settings.jwt_issuer, audience=settings.jwt_audience
            ),
            hasher=PasswordHasher(settings),
            policy=PasswordPolicy(min_length=settings.password_min_length),
            cipher=EnvelopeCipher(provider),
            rate_limiter=limiter,
            idempotency=idem,
            email=build_email_provider(settings.email_backend),
            redis=redis,
        )

    async def aclose(self) -> None:
        await self.engine.dispose()
        if self.redis is not None:
            await self.redis.aclose()
