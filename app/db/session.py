"""Async engine / session factory."""

from __future__ import annotations

from typing import Any

from sqlalchemy import event
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.core.config import Settings


def _sqlite_pragmas(dbapi_conn: Any, _: Any) -> None:
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA synchronous=NORMAL")  # safe with WAL; fsync on checkpoint
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


def create_engine(settings: Settings) -> AsyncEngine:
    if settings.is_sqlite:
        engine = create_async_engine(
            settings.database_url, echo=settings.database_echo, poolclass=NullPool
        )
        event.listen(engine.sync_engine, "connect", _sqlite_pragmas)
        return engine
    return create_async_engine(
        settings.database_url,
        echo=settings.database_echo,
        pool_size=settings.database_pool_size,
        max_overflow=settings.database_pool_size,
        pool_pre_ping=True,
        pool_recycle=1800,
    )


def create_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False, autoflush=False)
