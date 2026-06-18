# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Tests for SQLiteCache."""
from __future__ import annotations

import asyncio

import pytest

from src.infra.cache.sqlite import SQLiteCache


@pytest.fixture
def cache() -> SQLiteCache:
    return SQLiteCache(":memory:")


async def test_get_miss_returns_none(cache: SQLiteCache) -> None:
    assert await cache.get("missing") is None


async def test_set_and_get_returns_value(cache: SQLiteCache) -> None:
    await cache.set("k", {"x": 1}, ttl_seconds=60)
    assert await cache.get("k") == {"x": 1}


async def test_expired_entry_returns_none(cache: SQLiteCache) -> None:
    await cache.set("k", "value", ttl_seconds=1)
    # Manually expire by patching time — just sleep past TTL in a unit test
    # Use a 0-second TTL trick: set with ttl=1, then wait 2s is too slow.
    # Instead set an already-expired entry via raw SQL-like override.
    # Simpler: use ttl=0 which expires immediately (expires_at = now + 0).
    await cache.set("short", "gone", ttl_seconds=0)
    await asyncio.sleep(0.01)
    assert await cache.get("short") is None


async def test_overwrite_existing_key(cache: SQLiteCache) -> None:
    await cache.set("k", "first", ttl_seconds=60)
    await cache.set("k", "second", ttl_seconds=60)
    assert await cache.get("k") == "second"


async def test_delete_removes_entry(cache: SQLiteCache) -> None:
    await cache.set("k", "v", ttl_seconds=60)
    await cache.delete("k")
    assert await cache.get("k") is None


async def test_delete_nonexistent_is_noop(cache: SQLiteCache) -> None:
    await cache.delete("nonexistent")  # must not raise


async def test_stores_complex_value(cache: SQLiteCache) -> None:
    payload = {"nested": {"list": [1, 2, 3], "flag": True}}
    await cache.set("complex", payload, ttl_seconds=60)
    assert await cache.get("complex") == payload


async def test_clear_expired_removes_stale_entries(cache: SQLiteCache) -> None:
    await cache.set("stale", "v", ttl_seconds=0)
    await asyncio.sleep(0.01)
    deleted = await cache.clear_expired()
    assert deleted >= 1
    assert await cache.get("stale") is None


async def test_clear_expired_leaves_fresh_entries(cache: SQLiteCache) -> None:
    await cache.set("fresh", "keep", ttl_seconds=3600)
    await cache.clear_expired()
    assert await cache.get("fresh") == "keep"


async def test_strings_and_primitives_survive_serialization(cache: SQLiteCache) -> None:
    for key, val in [("s", "hello"), ("n", 42), ("f", 3.14), ("b", True)]:
        await cache.set(key, val, ttl_seconds=60)
        assert await cache.get(key) == val
