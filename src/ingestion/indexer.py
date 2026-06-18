# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""EVE event indexer — batched async writer from queue to EventStore.

Reads EveEvent objects from a dedicated asyncio queue (fed by the broadcaster)
and bulk-inserts them into the EventStore in batches of up to batch_size events,
flushing at least every flush_interval_ms milliseconds even if the batch is not full.

All event types are indexed (alert, dns, http, tls, flow, …). The dispatcher
handles alert-specific routing; the indexer is type-agnostic.

On flush failure, the batch is retained in memory for the next flush attempt
so that transient SQLite errors do not silently drop events (C3). If failures
persist, the batch grows — a structlog error is emitted on every failed flush
so operators see the problem without events being silently discarded.
"""
from __future__ import annotations

import asyncio

import structlog

from src.ingestion.models import EveEvent
from src.interfaces.event_store import EventStore

logger = structlog.get_logger(__name__)


class EveIndexer:
    """Drains the indexer queue and bulk-inserts EVE events into EventStore.

    Args:
        queue:             Source queue fed by the broadcaster.
        event_store:       Concrete EventStore implementation.
        batch_size:        Max events per insert transaction (VX_INDEXER_BATCH_SIZE).
        flush_interval_ms: Max ms to hold a partial batch (VX_INDEXER_BATCH_TIMEOUT_MS).
    """

    def __init__(
        self,
        queue: asyncio.Queue[EveEvent],
        event_store: EventStore,
        *,
        batch_size: int = 100,
        flush_interval_ms: int = 500,
    ) -> None:
        self._queue = queue
        self._event_store = event_store
        self._batch_size = batch_size
        self._flush_interval = flush_interval_ms / 1000.0

    async def run(self) -> None:
        """Index events until cancelled. Flushes any partial batch on cancellation."""
        batch: list[dict] = []
        logger.info("eve_indexer_started", batch_size=self._batch_size)
        try:
            while True:
                try:
                    event = await asyncio.wait_for(
                        self._queue.get(), timeout=self._flush_interval
                    )
                    batch.append(event.raw)
                    if len(batch) >= self._batch_size:
                        if await self._flush(batch):
                            batch = []
                        # On failure: keep batch; next iteration will retry
                except TimeoutError:
                    if batch:
                        if await self._flush(batch):
                            batch = []
                        # On failure: keep batch; next timeout will retry
        except asyncio.CancelledError:
            if batch:
                await self._flush(batch)
            logger.info("eve_indexer_stopped")
            raise

    async def _flush(self, batch: list[dict]) -> bool:
        """Attempt to write batch to EventStore. Returns True on success."""
        try:
            await self._event_store.insert_eve_events_batch(batch)
            logger.debug("eve_indexer_flush", count=len(batch))
            return True
        except Exception as exc:
            logger.error("eve_indexer_flush_failed", error=str(exc), count=len(batch))
            return False
