# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Alembic environment configuration.

Supports both offline (SQL script generation) and online (direct DB) migration modes.
The async engine is used for online mode to match the application's async stack.
DB URL is read from VX_DB_URL environment variable, falling back to the alembic.ini value.
"""
from __future__ import annotations

import asyncio
import os
from logging.config import fileConfig

from sqlalchemy.ext.asyncio import create_async_engine

from alembic import context
from src.infra.db.models import Base

config = context.config

# Wire up Python logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Import all models so Alembic sees them for autogenerate
target_metadata = Base.metadata


def _get_url() -> str:
    return os.environ.get("VX_DB_URL", config.get_main_option("sqlalchemy.url", ""))


def run_migrations_offline() -> None:
    """Generate SQL migration scripts without a live DB connection."""
    url = _get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Apply migrations against a live async database connection."""
    connectable = create_async_engine(_get_url())

    async with connectable.connect() as connection:
        await connection.run_sync(_do_run_migrations)

    await connectable.dispose()


def _do_run_migrations(connection: object) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)  # type: ignore[arg-type]
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
