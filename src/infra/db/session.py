# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Async SQLAlchemy engine and session factory.

Usage:
    from src.infra.db.session import get_session, init_db

    await init_db(db_path)          # call once at startup
    async with get_session() as session:
        result = await session.execute(...)

The engine is module-level state. Call init_db() exactly once before any
get_session() call. Tests call init_db() with an in-memory URL.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from src.errors.base import ProgrammerError
from src.infra.db.models import Base

_engine: AsyncEngine | None = None
_session_factory: async_sessionmaker[AsyncSession] | None = None


async def init_db(db_url: str = "sqlite+aiosqlite:///verdix.db") -> None:
    """Initialise the async engine and create all tables if they don't exist.

    Args:
        db_url: SQLAlchemy async URL. Defaults to a local file.
                Pass a file-based URL for tests (use pytest's tmp_path).
    """
    global _engine, _session_factory

    _engine = create_async_engine(
        db_url,
        echo=False,
        connect_args={"check_same_thread": False},
    )

    _session_factory = async_sessionmaker(
        _engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with _engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    """Dispose the engine. Call at application shutdown."""
    global _engine, _session_factory
    if _engine is not None:
        await _engine.dispose()
        _engine = None
        _session_factory = None


@asynccontextmanager
async def get_session() -> AsyncIterator[AsyncSession]:
    """Yield an AsyncSession, committing on success and rolling back on error."""
    if _session_factory is None:
        raise ProgrammerError(
            "Database not initialised — call init_db() first",
            detail="Call await init_db(db_url) exactly once at application startup.",
        )

    async with _session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


def get_engine() -> AsyncEngine:
    """Return the current engine. Used by Alembic env.py."""
    if _engine is None:
        raise ProgrammerError(
            "Database not initialised — call init_db() first",
            detail="Call await init_db(db_url) exactly once at application startup.",
        )
    return _engine
