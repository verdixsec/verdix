# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Integration tests for EvePipeline.

Runs the full tailer → broadcaster → indexer + dispatcher chain against a
temporary eve.json file and a real file-based SQLite EventStore. Uses async
polling so no fixed sleeps need to guess at timing.

File-based SQLite (tmp_path) rather than :memory: avoids connection-pool
issues: each new aiosqlite connection to :memory: gets a separate empty
database, so concurrent indexer and dispatcher sessions would see no schema.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from src.infra.db.event_store import SQLiteEventStore
from src.infra.db.session import close_db, init_db
from src.ingestion.pipeline import EvePipeline

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
async def fresh_db(tmp_path: Path) -> None:
    await close_db()  # defensive: dispose any engine left by a previous test
    db_file = tmp_path / "test.db"
    await init_db(f"sqlite+aiosqlite:///{db_file.as_posix()}")
    yield
    await close_db()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FAST = dict(
    poll_interval_ms=20,
    batch_size=10,
    flush_interval_ms=50,
    context_delay_seconds=0,
    daily_cap=300,
)


def _write(path: Path, event_type: str, flow_id: int, **extra) -> None:
    row = {"timestamp": "2026-05-09T12:00:00+0000", "flow_id": flow_id,
           "event_type": event_type, **extra}
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")


def _write_alert(path: Path, flow_id: int = 1, sig_id: int = 2000001) -> None:
    _write(
        path, "alert", flow_id,
        src_ip="10.0.0.1", src_port=54321,
        dest_ip="8.8.8.8", dest_port=80,
        proto="TCP", app_proto="http",
        alert={
            "action": "allowed", "signature_id": sig_id,
            "signature": "ET MALWARE Test", "severity": 1,
            "category": "Malware Command and Control Activity Detected",
        },
    )


async def _poll_until(async_pred, timeout: float = 3.0) -> None:
    """Await async_pred() every 50 ms until True or timeout."""
    deadline = asyncio.get_event_loop().time() + timeout
    while not await async_pred():
        if asyncio.get_event_loop().time() > deadline:
            raise TimeoutError("condition never satisfied within timeout")
        await asyncio.sleep(0.05)


async def _cancel(task: asyncio.Task) -> None:
    task.cancel()
    with pytest.raises((asyncio.CancelledError, Exception)):
        await task


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_pipeline_raises_on_missing_file(tmp_path: Path) -> None:
    store = SQLiteEventStore()
    pipeline = EvePipeline(tmp_path / "missing.json", store, **_FAST)
    with pytest.raises(FileNotFoundError):
        await pipeline.run()


async def test_pipeline_cancels_cleanly(tmp_path: Path) -> None:
    eve = tmp_path / "eve.json"
    eve.write_text("")
    store = SQLiteEventStore()
    task = asyncio.create_task(EvePipeline(eve, store, **_FAST).run())
    await asyncio.sleep(0.05)
    await _cancel(task)


async def test_non_alert_events_indexed_in_eve_events(tmp_path: Path) -> None:
    eve = tmp_path / "eve.json"
    eve.write_text("")
    store = SQLiteEventStore()
    task = asyncio.create_task(EvePipeline(eve, store, **_FAST).run())
    await asyncio.sleep(0.05)

    _write(eve, "dns", flow_id=10)
    _write(eve, "http", flow_id=10)
    _write(eve, "tls", flow_id=10)

    async def _ready() -> bool:
        return len(await store.get_correlated_events(10)) >= 3

    await _poll_until(_ready)
    await _cancel(task)

    events = await store.get_correlated_events(10)
    assert len(events) == 3
    assert {e["event_type"] for e in events} == {"dns", "http", "tls"}


async def test_alert_stored_in_alerts_table(tmp_path: Path) -> None:
    eve = tmp_path / "eve.json"
    eve.write_text("")
    store = SQLiteEventStore()
    task = asyncio.create_task(EvePipeline(eve, store, **_FAST).run())
    await asyncio.sleep(0.05)

    _write_alert(eve, flow_id=42, sig_id=2000001)

    async def _ready() -> bool:
        return len(await store.query_alerts()) >= 1

    await _poll_until(_ready)
    await _cancel(task)

    alerts = await store.query_alerts()
    assert len(alerts) == 1
    assert alerts[0]["flow_id"] == 42
    assert alerts[0]["signature_id"] == 2000001
    assert alerts[0]["status"] == "queued"


async def test_alert_also_indexed_in_eve_events(tmp_path: Path) -> None:
    """Alert events pass through the indexer too — they appear in eve_events
    so the triage pipeline can include them in the correlated context if needed."""
    eve = tmp_path / "eve.json"
    eve.write_text("")
    store = SQLiteEventStore()
    task = asyncio.create_task(EvePipeline(eve, store, **_FAST).run())
    await asyncio.sleep(0.05)

    _write_alert(eve, flow_id=99)

    async def _ready() -> bool:
        return len(await store.get_correlated_events(99)) >= 1

    await _poll_until(_ready)
    await _cancel(task)

    events = await store.get_correlated_events(99)
    assert any(e["event_type"] == "alert" for e in events)


async def test_alert_deferred_when_cap_reached(tmp_path: Path) -> None:
    eve = tmp_path / "eve.json"
    eve.write_text("")
    store = SQLiteEventStore()
    task = asyncio.create_task(
        EvePipeline(eve, store, **{**_FAST, "daily_cap": 0}).run()
    )
    await asyncio.sleep(0.05)

    _write_alert(eve, flow_id=7)

    async def _ready() -> bool:
        return len(await store.query_alerts()) >= 1

    await _poll_until(_ready)
    # Read before cancel: _cancel tears down async pool connections which can
    # leave the pool in a broken state if cleanup hits a CancelledError.
    alerts = await store.query_alerts()
    await _cancel(task)

    assert alerts[0]["status"] == "deferred"


async def test_mixed_events_routed_correctly(tmp_path: Path) -> None:
    """Realistic mix: 2 non-alerts + 1 alert on the same flow."""
    eve = tmp_path / "eve.json"
    eve.write_text("")
    store = SQLiteEventStore()
    task = asyncio.create_task(EvePipeline(eve, store, **_FAST).run())
    await asyncio.sleep(0.05)

    _write(eve, "dns", flow_id=55)
    _write(eve, "http", flow_id=55)
    _write_alert(eve, flow_id=55)

    async def _ready() -> bool:
        events = await store.get_correlated_events(55)
        alerts = await store.query_alerts()
        return len(events) >= 3 and len(alerts) >= 1

    await _poll_until(_ready)
    await _cancel(task)

    events = await store.get_correlated_events(55)
    alerts = await store.query_alerts()

    assert len(events) == 3           # dns + http + alert all indexed in eve_events
    assert len(alerts) == 1           # one row in alerts table
    assert alerts[0]["flow_id"] == 55
