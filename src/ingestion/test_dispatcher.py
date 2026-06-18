# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Tests for AlertDispatcher."""
from __future__ import annotations

import asyncio
from typing import Any

import pytest

from src.ingestion.dispatcher import AlertDispatcher
from src.ingestion.models import EveEvent

# ---------------------------------------------------------------------------
# Test double
# ---------------------------------------------------------------------------


class _CapturingStore:
    """Minimal EventStore test double for dispatcher tests."""

    def __init__(self, analyzed_today: int = 0) -> None:
        self.inserted: list[tuple[dict, str]] = []   # (raw_eve, status)
        self._analyzed_today = analyzed_today

    async def count_analyzed_today(self, sensor_id: int = 1) -> int:
        return self._analyzed_today

    async def insert_alert(self, alert: dict[str, Any], *, status: str = "queued") -> str:
        self.inserted.append((alert, status))
        return f"test-id-{len(self.inserted)}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FAST_DELAY = 0.02   # 20ms — exercises the delay path without slowing tests


def _make_alert_event(flow_id: int = 1) -> EveEvent:
    return EveEvent.from_dict({
        "timestamp": "2026-05-09T12:00:00+0000",
        "flow_id": flow_id,
        "event_type": "alert",
        "alert": {"signature_id": 2000001, "severity": 1},
    })


def _make_dns_event() -> EveEvent:
    return EveEvent.from_dict({
        "timestamp": "2026-05-09T12:00:00+0000",
        "flow_id": 1,
        "event_type": "dns",
    })


async def _wait_until(predicate, timeout: float = 2.0, interval: float = 0.01) -> None:
    deadline = asyncio.get_event_loop().time() + timeout
    while not predicate():
        if asyncio.get_event_loop().time() > deadline:
            raise TimeoutError("predicate never became true")
        await asyncio.sleep(interval)


async def _cancel(task: asyncio.Task) -> None:
    task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await task


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------


async def test_non_alert_events_are_ignored() -> None:
    """DNS, flow, http etc. must pass through without being inserted."""
    queue: asyncio.Queue[EveEvent] = asyncio.Queue()
    store = _CapturingStore()
    dispatcher = AlertDispatcher(queue, store, context_delay_seconds=0, daily_cap=300)
    task = asyncio.create_task(dispatcher.run())

    await queue.put(_make_dns_event())
    await queue.put(_make_dns_event())

    # Give dispatcher time to process, then confirm nothing inserted
    await asyncio.sleep(0.05)
    await _cancel(task)

    assert store.inserted == []


async def test_alert_event_is_inserted() -> None:
    queue: asyncio.Queue[EveEvent] = asyncio.Queue()
    store = _CapturingStore()
    dispatcher = AlertDispatcher(queue, store, context_delay_seconds=0, daily_cap=300)
    task = asyncio.create_task(dispatcher.run())

    await queue.put(_make_alert_event(flow_id=42))

    await _wait_until(lambda: len(store.inserted) == 1)
    await _cancel(task)

    raw, status = store.inserted[0]
    assert raw["flow_id"] == 42
    assert raw["event_type"] == "alert"


# ---------------------------------------------------------------------------
# Context delay
# ---------------------------------------------------------------------------


async def test_context_delay_is_applied() -> None:
    """Alert must not be inserted before the context delay has elapsed."""
    queue: asyncio.Queue[EveEvent] = asyncio.Queue()
    store = _CapturingStore()
    dispatcher = AlertDispatcher(
        queue, store, context_delay_seconds=_FAST_DELAY, daily_cap=300
    )
    task = asyncio.create_task(dispatcher.run())

    await queue.put(_make_alert_event())

    # Before delay expires: nothing inserted
    await asyncio.sleep(_FAST_DELAY / 2)
    assert store.inserted == []

    # After delay expires: inserted
    await _wait_until(lambda: len(store.inserted) == 1)
    await _cancel(task)

    assert len(store.inserted) == 1


# ---------------------------------------------------------------------------
# Daily cap / status assignment
# ---------------------------------------------------------------------------


async def test_alert_under_cap_gets_queued_status() -> None:
    queue: asyncio.Queue[EveEvent] = asyncio.Queue()
    store = _CapturingStore(analyzed_today=0)
    dispatcher = AlertDispatcher(queue, store, context_delay_seconds=0, daily_cap=300)
    task = asyncio.create_task(dispatcher.run())

    await queue.put(_make_alert_event())

    await _wait_until(lambda: len(store.inserted) == 1)
    await _cancel(task)

    _, status = store.inserted[0]
    assert status == "queued"


async def test_alert_at_cap_gets_deferred_status() -> None:
    """When count_analyzed_today() == daily_cap, status must be 'deferred'."""
    queue: asyncio.Queue[EveEvent] = asyncio.Queue()
    store = _CapturingStore(analyzed_today=300)
    dispatcher = AlertDispatcher(queue, store, context_delay_seconds=0, daily_cap=300)
    task = asyncio.create_task(dispatcher.run())

    await queue.put(_make_alert_event())

    await _wait_until(lambda: len(store.inserted) == 1)
    await _cancel(task)

    _, status = store.inserted[0]
    assert status == "deferred"


async def test_alert_over_cap_gets_deferred_status() -> None:
    queue: asyncio.Queue[EveEvent] = asyncio.Queue()
    store = _CapturingStore(analyzed_today=999)
    dispatcher = AlertDispatcher(queue, store, context_delay_seconds=0, daily_cap=300)
    task = asyncio.create_task(dispatcher.run())

    await queue.put(_make_alert_event())

    await _wait_until(lambda: len(store.inserted) == 1)
    await _cancel(task)

    _, status = store.inserted[0]
    assert status == "deferred"


# ---------------------------------------------------------------------------
# Multiple alerts
# ---------------------------------------------------------------------------


async def test_multiple_alerts_all_inserted() -> None:
    queue: asyncio.Queue[EveEvent] = asyncio.Queue()
    store = _CapturingStore()
    dispatcher = AlertDispatcher(queue, store, context_delay_seconds=0, daily_cap=300)
    task = asyncio.create_task(dispatcher.run())

    for fid in [10, 20, 30]:
        await queue.put(_make_alert_event(flow_id=fid))

    await _wait_until(lambda: len(store.inserted) == 3)
    await _cancel(task)

    flow_ids = [raw["flow_id"] for raw, _ in store.inserted]
    assert sorted(flow_ids) == [10, 20, 30]


# ---------------------------------------------------------------------------
# Cancellation
# ---------------------------------------------------------------------------


async def test_cancel_during_delay_does_not_insert() -> None:
    """If cancelled while sleeping the context delay, the alert is not inserted."""
    queue: asyncio.Queue[EveEvent] = asyncio.Queue()
    store = _CapturingStore()
    dispatcher = AlertDispatcher(
        queue, store, context_delay_seconds=5.0, daily_cap=300
    )
    task = asyncio.create_task(dispatcher.run())

    await queue.put(_make_alert_event())
    await asyncio.sleep(0.05)   # let dispatcher pick up the event and start sleeping

    await _cancel(task)

    assert store.inserted == []
