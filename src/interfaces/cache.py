# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Cache interface — abstract over time-bounded key-value caching.

Concrete implementations:
  v0.1  src/infra/cache/memory.py  — in-memory TTL dict (Days 7-8 onward)
  v0.1  src/infra/cache/sqlite.py  — SQLite-backed (Days 8-10, enrichment layer)
  v1.x  Redis (swap target for multi-node deployments)

Application code must import this Protocol, never a concrete class.
"""
from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class Cache(Protocol):
    """Time-bounded key-value cache."""

    async def get(self, key: str) -> Any | None:
        """Return cached value, or None if missing or expired."""
        ...

    async def set(self, key: str, value: Any, ttl_seconds: int) -> None:
        """Store value with a TTL. Overwrites any existing entry."""
        ...

    async def delete(self, key: str) -> None:
        """Remove a single entry (no-op if absent)."""
        ...
