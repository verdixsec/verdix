# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""SQLite-backed TTL cache — implements the Cache Protocol for persistent enrichment caching.

Each SQLiteCache instance holds a single persistent aiosqlite connection so that
":memory:" databases work correctly in tests (separate connect() calls would each
get a fresh empty database).  File-based databases benefit too: fewer open/close
cycles per operation.

Each enrichment provider uses a distinct key prefix:
  vt:{indicator_type}:{value}      — VirusTotal
  rdap:{domain}                    — RDAP
  rdap:bootstrap                   — IANA RDAP bootstrap registry

GeoIP does not use this cache at all — it's a local MMDB file read with
no network call to rate-limit, so there's no "geoip:{ip}" key here.
"""
from __future__ import annotations

import json
import time
from typing import Any

import aiosqlite


class SQLiteCache:
    """Persistent key-value cache backed by a single SQLite connection.

    Args:
        db_path: Path to the SQLite file.
                 Use ':memory:' in tests for an ephemeral in-process cache.
    """

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._conn: aiosqlite.Connection | None = None

    async def _get_conn(self) -> aiosqlite.Connection:
        """Return the persistent connection, initialising the schema on first use."""
        if self._conn is None:
            self._conn = await aiosqlite.connect(self._db_path)
            await self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cache_entries (
                    cache_key   TEXT PRIMARY KEY,
                    cache_value TEXT NOT NULL,
                    expires_at  REAL NOT NULL
                )
                """
            )
            await self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_cache_expires ON cache_entries(expires_at)"
            )
            await self._conn.commit()
        return self._conn

    async def get(self, key: str) -> Any | None:
        conn = await self._get_conn()
        now = time.time()
        async with conn.execute(
            "SELECT cache_value, expires_at FROM cache_entries WHERE cache_key = ?",
            (key,),
        ) as cursor:
            row = await cursor.fetchone()

        if row is None:
            return None

        cache_value, expires_at = row
        if now > expires_at:
            await conn.execute(
                "DELETE FROM cache_entries WHERE cache_key = ?", (key,)
            )
            await conn.commit()
            return None

        return json.loads(cache_value)

    async def set(self, key: str, value: Any, ttl_seconds: int) -> None:
        expires_at = time.time() + ttl_seconds
        serialized = json.dumps(value)
        conn = await self._get_conn()
        await conn.execute(
            """
            INSERT INTO cache_entries (cache_key, cache_value, expires_at)
            VALUES (?, ?, ?)
            ON CONFLICT(cache_key) DO UPDATE SET
                cache_value = excluded.cache_value,
                expires_at  = excluded.expires_at
            """,
            (key, serialized, expires_at),
        )
        await conn.commit()

    async def delete(self, key: str) -> None:
        conn = await self._get_conn()
        await conn.execute(
            "DELETE FROM cache_entries WHERE cache_key = ?", (key,)
        )
        await conn.commit()

    async def clear_expired(self) -> int:
        """Delete all expired entries. Returns the count of rows deleted."""
        conn = await self._get_conn()
        cursor = await conn.execute(
            "DELETE FROM cache_entries WHERE expires_at < ?", (time.time(),)
        )
        await conn.commit()
        return cursor.rowcount

    async def close(self) -> None:
        """Close the database connection. Call at application shutdown."""
        if self._conn is not None:
            await self._conn.close()
            self._conn = None
