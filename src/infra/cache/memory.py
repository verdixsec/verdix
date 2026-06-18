# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""In-memory TTL cache — implements the Cache Protocol using a plain dict.

Used by the reverse DNS identity provider (Days 7-8) and as a test double
for enrichment clients (Days 8-10). The SQLite-backed implementation
(src/infra/cache/sqlite.py) ships in Days 8-10 for persistent enrichment caching.

Single-threaded asyncio safe; no locking needed.
"""
from __future__ import annotations

import time
from typing import Any


class InMemoryTTLCache:
    """In-memory cache with per-entry TTL. Expired entries are evicted on access."""

    def __init__(self) -> None:
        self._store: dict[str, tuple[Any, float]] = {}  # key → (value, expiry_monotonic)

    async def get(self, key: str) -> Any | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        value, expiry = entry
        if time.monotonic() > expiry:
            del self._store[key]
            return None
        return value

    async def set(self, key: str, value: Any, ttl_seconds: int) -> None:
        self._store[key] = (value, time.monotonic() + ttl_seconds)

    async def delete(self, key: str) -> None:
        self._store.pop(key, None)
