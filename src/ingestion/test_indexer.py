# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Tests for EveIndexer.

Uses a _CapturingStore test double rather than a real SQLite DB to keep tests
fast and focused on indexer behaviour (batching, timeout, cancel-flush).
Deterministic waiting via asyncio.wait_for on a store-level asyncio.Event
avoids the fixed-sleep timing brittleness seen on Windows IocpProactor.
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from src.ingestion.indexer import EveIndexer
from src.ingestion.models import EveEvent

# ---------------------------------------------------------------------------
# Test double
# ---------------------------------------------------------------------------


class _CapturingStore:
    """Minimal EventStore test double that records every batch written."""

    def __init__(self) -> None:
        self.batches: list[list[dict]] = []
        self._flush_count = 0
        self._flush_event = asyncio.Event()

    async def insert_eve_events_batch(self, events: list[dict[str, Any]]) -> None:
        self.batches.append(list(events))
        self._flush_count += 1
        self._flush_event.set()

    async def wait_flushes(self, n: int, timeout: float = 2.0) -> None:
        """Block until at least n total flushes have occurred.

        Uses a monotone counter so back-to-back rapid flushes are never missed,
        even if they all complete before this method is first called.
        """
        deadline = asyncio.get_event_loop().time() + timeout
        while self._flush_count < n:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise TimeoutError(f"expected {n} flushes, got {self._flush_count}")
            self._flush_event.clear()
            try:
                await asyncio.wait_for(self._flush_event.wait(), timeout=remaining)
            except TimeoutError:
                raise TimeoutError(f"expected {n} flushes, got {self._flush_count}")

    @property
    def total_events(self) -> int:
        return sum(len(b) for b in self.batches)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(event_type: str = "dns", flow_id: int = 1) -> EveEvent:
    raw = {
        "timestamp": "2026-05-09T12:00:00+0000",
        "flow_id": flow_id,
        "event_type": event_type,
    }
    return EveEvent.from_dict(raw)


async def _cancel(task: asyncio.Task) -> None:
    task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await task


# ---------------------------------------------------------------------------
# Batch-size flush
# ---------------------------------------------------------------------------


async def test_full_batch_flushed_immediately() -> None:
    """When batch_size events arrive, flush without waiting for the timeout."""
    queue: asyncio.Queue[EveEvent] = asyncio.Queue()
    store = _CapturingStore()
    indexer = EveIndexer(queue, store, batch_size=3, flush_interval_ms=5_000)
    task = asyncio.create_task(indexer.run())

    for i in range(3):
        await queue.put(_make_event("dns", flow_id=i))

    await store.wait_flushes(1)
    await _cancel(task)

    assert len(store.batches) == 1
    assert store.total_events == 3


async def test_batch_contains_correct_raw_dicts() -> None:
    queue: asyncio.Queue[EveEvent] = asyncio.Queue()
    store = _CapturingStore()
    indexer = EveIndexer(queue, store, batch_size=2, flush_interval_ms=5_000)
    task = asyncio.create_task(indexer.run())

    await queue.put(_make_event("http", flow_id=10))
    await queue.put(_make_event("tls", flow_id=20))

    await store.wait_flushes(1)
    await _cancel(task)

    batch = store.batches[0]
    assert batch[0]["event_type"] == "http"
    assert batch[0]["flow_id"] == 10
    assert batch[1]["event_type"] == "tls"
    assert batch[1]["flow_id"] == 20


# ---------------------------------------------------------------------------
# Timeout flush
# ---------------------------------------------------------------------------


async def test_partial_batch_flushed_on_timeout() -> None:
    """Events fewer than batch_size are flushed when the interval expires."""
    queue: asyncio.Queue[EveEvent] = asyncio.Queue()
    store = _CapturingStore()
    indexer = EveIndexer(queue, store, batch_size=100, flush_interval_ms=50)
    task = asyncio.create_task(indexer.run())

    await queue.put(_make_event("flow"))
    await queue.put(_make_event("dns"))

    await store.wait_flushes(1)
    await _cancel(task)

    assert store.total_events == 2


async def test_empty_queue_no_flush_no_error() -> None:
    """An idle indexer should never flush and should cancel cleanly."""
    queue: asyncio.Queue[EveEvent] = asyncio.Queue()
    store = _CapturingStore()
    indexer = EveIndexer(queue, store, batch_size=10, flush_interval_ms=50)
    task = asyncio.create_task(indexer.run())

    await asyncio.sleep(0.12)  # survive a couple of timeout cycles
    await _cancel(task)

    assert store.total_events == 0


# ---------------------------------------------------------------------------
# Cancel flush
# ---------------------------------------------------------------------------


async def test_partial_batch_flushed_on_cancel() -> None:
    """Events in an incomplete batch must be written when the task is cancelled."""
    queue: asyncio.Queue[EveEvent] = asyncio.Queue()
    store = _CapturingStore()
    indexer = EveIndexer(queue, store, batch_size=100, flush_interval_ms=5_000)
    task = asyncio.create_task(indexer.run())

    # Put 5 events — well below batch_size, timeout is huge, so nothing flushes yet
    for i in range(5):
        await queue.put(_make_event("http", flow_id=i))

    # Drain queue before cancelling so all events are in the batch
    while not queue.empty():
        await asyncio.sleep(0)

    await _cancel(task)

    assert store.total_events == 5


async def test_cancel_with_empty_batch_is_clean() -> None:
    queue: asyncio.Queue[EveEvent] = asyncio.Queue()
    store = _CapturingStore()
    indexer = EveIndexer(queue, store, batch_size=10, flush_interval_ms=5_000)
    task = asyncio.create_task(indexer.run())
    await asyncio.sleep(0)
    await _cancel(task)

    assert store.total_events == 0


# ---------------------------------------------------------------------------
# Multiple batches
# ---------------------------------------------------------------------------


async def test_multiple_batches_all_stored() -> None:
    """Events exceeding batch_size should produce multiple flushes."""
    queue: asyncio.Queue[EveEvent] = asyncio.Queue()
    store = _CapturingStore()
    indexer = EveIndexer(queue, store, batch_size=4, flush_interval_ms=5_000)
    task = asyncio.create_task(indexer.run())

    for i in range(10):
        await queue.put(_make_event("dns", flow_id=i))

    await store.wait_flushes(2)  # monotone counter: safe even if both fired already
    await _cancel(task)

    assert store.total_events >= 8
    assert all(len(b) <= 4 for b in store.batches)
