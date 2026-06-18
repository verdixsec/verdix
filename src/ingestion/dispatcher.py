# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Alert dispatcher — delays alerts then writes them to the alerts table.

Reads EveEvent objects from a dedicated asyncio queue (fed by the broadcaster),
ignores non-alert events, waits VX_FLOW_CONTEXT_DELAY_SECONDS so that
correlated flow/http/dns records have time to land in the EventStore, then
determines queue status (queued vs deferred) and calls insert_alert.

ADR-002: the 30-second delay catches >95% of Suricata flow records, which are
flushed when the flow ends — often 10-30 seconds after the alert that fired.
ADR-009: alerts that would exceed the daily cap (VX_TRIAGE_DAILY_CAP) are stored as 'deferred'.

Each alert is handled concurrently (asyncio.create_task) so that the 30-second
context-delay for alert N does not block alert N+1. A per-dispatcher asyncio.Lock
serialises the count+insert pair to avoid a TOCTOU race on the daily cap.
"""
from __future__ import annotations

import asyncio

import structlog

from src.ingestion.models import EveEvent
from src.interfaces.event_store import EventStore

logger = structlog.get_logger(__name__)


class AlertDispatcher:
    """Delays alert events then persists them with the correct queue status.

    Args:
        queue:                   Source queue fed by the broadcaster.
        event_store:             Concrete EventStore implementation.
        context_delay_seconds:   Seconds to wait before inserting (VX_FLOW_CONTEXT_DELAY_SECONDS).
        daily_cap:               Max non-deferred alerts per day (VX_TRIAGE_DAILY_CAP).
    """

    def __init__(
        self,
        queue: asyncio.Queue[EveEvent],
        event_store: EventStore,
        *,
        context_delay_seconds: float = 30.0,
        daily_cap: int = 300,
    ) -> None:
        self._queue = queue
        self._event_store = event_store
        self._context_delay = context_delay_seconds
        self._daily_cap = daily_cap
        # Serialises count_analyzed_today + insert_alert so concurrent _handle
        # tasks don't race on the daily cap check (C1).
        self._cap_lock = asyncio.Lock()

    async def run(self) -> None:
        """Dispatch alerts until cancelled.

        Each alert spawns an independent asyncio task that handles the
        context-delay sleep and DB insert, so parallel alerts don't block
        each other (I1). All pending tasks are cancelled cleanly on shutdown.
        """
        pending: set[asyncio.Task[None]] = set()
        logger.info("alert_dispatcher_started", context_delay=self._context_delay)
        try:
            while True:
                event = await self._queue.get()
                if not event.is_alert:
                    continue
                task: asyncio.Task[None] = asyncio.create_task(self._handle(event))
                pending.add(task)
                task.add_done_callback(pending.discard)
        except asyncio.CancelledError:
            for task in pending:
                task.cancel()
            if pending:
                await asyncio.gather(*pending, return_exceptions=True)
            logger.info("alert_dispatcher_stopped")
            raise

    async def _handle(self, event: EveEvent) -> None:
        """Apply context delay, determine cap status, persist alert."""
        await asyncio.sleep(self._context_delay)
        async with self._cap_lock:
            count = await self._event_store.count_analyzed_today()
            status = "queued" if count < self._daily_cap else "deferred"
            try:
                alert_id = await self._event_store.insert_alert(event.raw, status=status)
            except Exception as exc:
                logger.error(
                    "alert_dispatcher_insert_failed",
                    flow_id=event.flow_id,
                    error=str(exc),
                )
                return
        logger.info(
            "alert_dispatcher_inserted",
            alert_id=alert_id,
            flow_id=event.flow_id,
            status=status,
        )
