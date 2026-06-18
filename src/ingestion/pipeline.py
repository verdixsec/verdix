# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""EVE ingestion pipeline — wires tailer, broadcaster, indexer, and dispatcher.

Fan-out pattern (ADR-001, ADR-002):

    eve.json
        └── EveTailer        → tailer_queue
                └── _broadcast
                        ├── indexer_queue  → EveIndexer  → EventStore (eve_events)
                        └── dispatcher_queue → AlertDispatcher → EventStore (alerts)

The broadcaster sends every event to the indexer queue and only alert events
to the dispatcher queue. Each downstream component handles its own filtering.

If any component raises an unexpected exception the pipeline cancels the
remaining tasks and re-raises, so the caller can surface the failure and
restart or alert.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import structlog

from src.ingestion.dispatcher import AlertDispatcher
from src.ingestion.indexer import EveIndexer
from src.ingestion.models import EveEvent
from src.ingestion.tailer import EveTailer
from src.interfaces.event_store import EventStore

logger = structlog.get_logger(__name__)


async def _broadcast(
    source: asyncio.Queue[EveEvent],
    indexer_queue: asyncio.Queue[EveEvent],
    dispatcher_queue: asyncio.Queue[EveEvent],
) -> None:
    """Fan-out: all events → indexer; alert events only → dispatcher."""
    while True:
        event = await source.get()
        await indexer_queue.put(event)
        if event.is_alert:
            await dispatcher_queue.put(event)


class EvePipeline:
    """Composes the four ingestion components and runs them as concurrent tasks.

    Args:
        eve_path:              Path to eve.json (local or NFS/SMB mount).
        event_store:           Concrete EventStore implementation.
        poll_interval_ms:      Tailer polling interval (VX_EVE_POLL_INTERVAL_MS).
        batch_size:            Indexer batch size (VX_INDEXER_BATCH_SIZE).
        flush_interval_ms:     Indexer flush timeout (VX_INDEXER_BATCH_TIMEOUT_MS).
        context_delay_seconds: Dispatcher delay before alert insert (VX_FLOW_CONTEXT_DELAY_SECONDS).
        daily_cap:             Max non-deferred alerts per day (VX_TRIAGE_DAILY_CAP).
    """

    def __init__(
        self,
        eve_path: str | Path,
        event_store: EventStore,
        *,
        poll_interval_ms: int = 500,
        batch_size: int = 100,
        flush_interval_ms: int = 500,
        context_delay_seconds: float = 30.0,
        daily_cap: int = 300,
    ) -> None:
        self._tailer_queue: asyncio.Queue[EveEvent] = asyncio.Queue()
        self._indexer_queue: asyncio.Queue[EveEvent] = asyncio.Queue()
        self._dispatcher_queue: asyncio.Queue[EveEvent] = asyncio.Queue()

        self._tailer = EveTailer(
            eve_path, self._tailer_queue, poll_interval_ms=poll_interval_ms
        )
        self._indexer = EveIndexer(
            self._indexer_queue, event_store,
            batch_size=batch_size, flush_interval_ms=flush_interval_ms,
        )
        self._dispatcher = AlertDispatcher(
            self._dispatcher_queue, event_store,
            context_delay_seconds=context_delay_seconds, daily_cap=daily_cap,
        )

    async def run(self) -> None:
        """Run all pipeline components until cancelled or first failure."""
        tasks = [
            asyncio.create_task(self._tailer.run(), name="tailer"),
            asyncio.create_task(
                _broadcast(
                    self._tailer_queue, self._indexer_queue, self._dispatcher_queue
                ),
                name="broadcaster",
            ),
            asyncio.create_task(self._indexer.run(), name="indexer"),
            asyncio.create_task(self._dispatcher.run(), name="dispatcher"),
        ]
        logger.info("eve_pipeline_started")
        try:
            await asyncio.gather(*tasks)
        except (asyncio.CancelledError, Exception):
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
