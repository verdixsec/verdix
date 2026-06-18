# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Nightly EVE event cleanup task (ADR-003).

Deletes raw EVE context events older than VX_EVE_CONTEXT_RETENTION_DAYS (default 7).
Alerts are retained indefinitely — they form the disposition training corpus.

Usage:
    cleanup = EveCleanupTask(event_store)
    await cleanup.run_once()          # single pass (for testing / manual trigger)
    await cleanup.run_nightly()       # infinite loop, runs once per day
"""
from __future__ import annotations

import asyncio
import os

import structlog

from src.interfaces.event_store import EventStore

logger = structlog.get_logger(__name__)

_DEFAULT_RETENTION_DAYS = int(os.environ.get("VX_EVE_CONTEXT_RETENTION_DAYS", "7"))
_SECONDS_PER_DAY = 86_400


class EveCleanupTask:
    """Deletes expired EVE context events on a nightly schedule.

    Args:
        event_store:     EventStore implementation.
        retention_days:  Events older than this are deleted (SC_EVE_CONTEXT_RETENTION_DAYS).
    """

    def __init__(
        self,
        event_store: EventStore,
        *,
        retention_days: int = _DEFAULT_RETENTION_DAYS,
    ) -> None:
        self._event_store = event_store
        self._retention_days = retention_days

    async def run_once(self) -> int:
        """Delete expired EVE events. Returns number of rows deleted."""
        deleted = await self._event_store.delete_expired_eve_events(self._retention_days)
        logger.info(
            "eve_cleanup_complete",
            deleted=deleted,
            retention_days=self._retention_days,
        )
        return deleted

    async def run_nightly(self) -> None:
        """Infinite loop — runs cleanup once per day, then sleeps 24 hours."""
        logger.info("eve_cleanup_task_started", retention_days=self._retention_days)
        while True:
            try:
                await self.run_once()
            except asyncio.CancelledError:
                logger.info("eve_cleanup_task_stopped")
                raise
            except Exception as exc:
                logger.error("eve_cleanup_failed", error=str(exc))
            await asyncio.sleep(_SECONDS_PER_DAY)
