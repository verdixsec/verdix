# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Tests for EveTailer.

Uses tmp_path + asyncio tasks. Events are awaited directly from the queue with
a generous timeout instead of fixed sleeps, which avoids timing brittleness on
Windows IocpProactor where sleep granularity is coarser than on Linux.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from src.ingestion.models import EveEvent, EventType
from src.ingestion.tailer import EveTailer

_POLL_MS = 20           # poll interval for test tailers
_EVENT_TIMEOUT = 2.0    # max seconds to wait for an event to appear in queue


def _write_eve_line(path: Path, event_type: str, flow_id: int = 1) -> None:
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({
            "timestamp": "2026-05-09T12:00:00.000000+0000",
            "flow_id": flow_id,
            "event_type": event_type,
        }) + "\n")


async def _drain_queue(queue: asyncio.Queue[EveEvent], count: int) -> list[EveEvent]:
    """Await exactly `count` events from queue, raising on timeout."""
    return [await asyncio.wait_for(queue.get(), timeout=_EVENT_TIMEOUT) for _ in range(count)]


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------


async def test_run_raises_if_path_missing(tmp_path: Path) -> None:
    queue: asyncio.Queue[EveEvent] = asyncio.Queue()
    tailer = EveTailer(tmp_path / "missing.json", queue, poll_interval_ms=_POLL_MS)
    with pytest.raises(FileNotFoundError):
        await tailer.run()


async def test_pre_existing_lines_are_not_read(tmp_path: Path) -> None:
    """Lines already in the file when tailer starts must be skipped (tail from end)."""
    eve = tmp_path / "eve.json"
    _write_eve_line(eve, "dns")
    _write_eve_line(eve, "http")

    queue: asyncio.Queue[EveEvent] = asyncio.Queue()
    tailer = EveTailer(eve, queue, poll_interval_ms=_POLL_MS)
    task = asyncio.create_task(tailer.run())
    # Give tailer a few poll cycles, then confirm nothing queued
    await asyncio.sleep(_POLL_MS * 3 / 1000)
    task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await task
    assert queue.empty()


# ---------------------------------------------------------------------------
# Normal ingestion
# ---------------------------------------------------------------------------


async def test_new_lines_emitted_to_queue(tmp_path: Path) -> None:
    eve = tmp_path / "eve.json"
    eve.write_text("")  # empty file — position = 0

    queue: asyncio.Queue[EveEvent] = asyncio.Queue()
    tailer = EveTailer(eve, queue, poll_interval_ms=_POLL_MS)
    task = asyncio.create_task(tailer.run())

    # Wait one poll cycle so tailer initialises and positions itself at EOF
    await asyncio.sleep(_POLL_MS * 2 / 1000)
    _write_eve_line(eve, "dns", flow_id=42)
    _write_eve_line(eve, "tls", flow_id=43)

    try:
        events = await _drain_queue(queue, 2)
    finally:
        task.cancel()
        with pytest.raises((asyncio.CancelledError, Exception)):
            await task

    assert events[0].event_type == EventType.DNS
    assert events[0].flow_id == 42
    assert events[1].event_type == EventType.TLS
    assert events[1].flow_id == 43


async def test_empty_lines_skipped(tmp_path: Path) -> None:
    eve = tmp_path / "eve.json"
    eve.write_text("")

    queue: asyncio.Queue[EveEvent] = asyncio.Queue()
    tailer = EveTailer(eve, queue, poll_interval_ms=_POLL_MS)
    task = asyncio.create_task(tailer.run())
    await asyncio.sleep(_POLL_MS * 2 / 1000)

    with eve.open("a") as fh:
        fh.write("\n\n")
    _write_eve_line(eve, "http")

    try:
        events = await _drain_queue(queue, 1)
    finally:
        task.cancel()
        with pytest.raises((asyncio.CancelledError, Exception)):
            await task

    assert events[0].event_type == EventType.HTTP
    assert queue.empty()  # no phantom events from blank lines


# ---------------------------------------------------------------------------
# Malformed JSON
# ---------------------------------------------------------------------------


async def test_malformed_json_line_skipped(tmp_path: Path) -> None:
    eve = tmp_path / "eve.json"
    eve.write_text("")

    queue: asyncio.Queue[EveEvent] = asyncio.Queue()
    tailer = EveTailer(eve, queue, poll_interval_ms=_POLL_MS)
    task = asyncio.create_task(tailer.run())
    await asyncio.sleep(_POLL_MS * 2 / 1000)

    with eve.open("a") as fh:
        fh.write("NOT JSON\n")
    _write_eve_line(eve, "flow")

    try:
        events = await _drain_queue(queue, 1)
    finally:
        task.cancel()
        with pytest.raises((asyncio.CancelledError, Exception)):
            await task

    assert events[0].event_type == EventType.FLOW
    assert queue.empty()  # bad line produced no event


# ---------------------------------------------------------------------------
# Log rotation
# ---------------------------------------------------------------------------


async def test_rotation_detected_via_size_regression(tmp_path: Path) -> None:
    """Simulate rotation by replacing file with shorter content."""
    eve = tmp_path / "eve.json"
    # Large initial content so tailer's starting position is well above zero
    with eve.open("w") as fh:
        fh.write("x" * 500 + "\n")

    queue: asyncio.Queue[EveEvent] = asyncio.Queue()
    tailer = EveTailer(eve, queue, poll_interval_ms=_POLL_MS)
    task = asyncio.create_task(tailer.run())
    await asyncio.sleep(_POLL_MS * 2 / 1000)  # tailer initialises at position ~501

    # Rotation: replace file with shorter new content
    eve.write_text(json.dumps({
        "timestamp": "2026-05-09T13:00:00+0000",
        "flow_id": 99,
        "event_type": "http",
    }) + "\n")

    try:
        events = await _drain_queue(queue, 1)
    finally:
        task.cancel()
        with pytest.raises((asyncio.CancelledError, Exception)):
            await task

    assert events[0].event_type == EventType.HTTP
    assert events[0].flow_id == 99
