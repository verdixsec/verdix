# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Tests for SQLiteEventStore.

Each test gets a fresh in-memory SQLite database via the autouse fixture.
asyncio_mode = "auto" is set in pyproject.toml — no @pytest.mark.asyncio needed.
"""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import sqlalchemy as sa

from src.infra.db.event_store import SQLiteEventStore
from src.infra.db.models import Alert
from src.infra.db.operational_store import SQLiteOperationalStore
from src.infra.db.session import close_db, get_session, init_db
from src.interfaces.event_store import EventStore

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
async def fresh_db() -> None:
    """Reinitialise an in-memory DB before each test and close after."""
    await init_db("sqlite+aiosqlite:///:memory:")
    yield
    await close_db()


@pytest.fixture
def store() -> SQLiteEventStore:
    return SQLiteEventStore()


@pytest.fixture
def op_store() -> SQLiteOperationalStore:
    return SQLiteOperationalStore()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ts(offset_seconds: int = 0) -> str:
    """Return an ISO-8601 UTC timestamp offset from now by offset_seconds."""
    return (datetime.now(UTC) + timedelta(seconds=offset_seconds)).isoformat()


def _make_alert(
    flow_id: int = 12345,
    src_ip: str = "10.0.0.1",
    dest_ip: str = "8.8.8.8",
    sig_id: int = 2000001,
    sig_msg: str = "ET MALWARE Test",
    severity: int = 1,
    timestamp: str | None = None,
) -> dict:
    return {
        "timestamp": timestamp or _ts(),
        "flow_id": flow_id,
        "event_type": "alert",
        "src_ip": src_ip,
        "src_port": 54321,
        "dest_ip": dest_ip,
        "dest_port": 80,
        "proto": "TCP",
        "app_proto": "http",
        "alert": {
            "action": "allowed",
            "signature_id": sig_id,
            "signature": sig_msg,
            "severity": severity,
            "category": "A Network Trojan was Detected",
        },
    }


def _make_eve_event(
    event_type: str = "dns", flow_id: int = 12345, timestamp: str | None = None
) -> dict:
    return {
        "timestamp": timestamp or _ts(),
        "flow_id": flow_id,
        "event_type": event_type,
        "dns": {"type": "query", "rrname": "example.com"},
    }


async def _seed_analyzed_alert(
    store: SQLiteEventStore,
    op_store: SQLiteOperationalStore,
    *,
    llm_inputs: dict,
    ingest_timestamp: str,
    sig_id: int = 2000001,
    src_ip: str = "10.0.0.1",
    dest_ip: str = "8.8.8.8",
) -> tuple[str, str]:
    """Insert an alert, give it an 'analyzed' verdict with the given llm_inputs
    shape, and backdate ingest_timestamp — insert_alert() always stamps 'now',
    so tests that need deterministic relative ordering patch it directly."""
    alert_id = await store.insert_alert(_make_alert(sig_id=sig_id, src_ip=src_ip, dest_ip=dest_ip))
    async with get_session() as session:
        await session.execute(
            sa.update(Alert)
            .where(Alert.alert_id == alert_id)
            .values(ingest_timestamp=ingest_timestamp)
        )
    verdict_id = str(uuid.uuid4())
    await op_store.record_verdict({
        "verdict_id": verdict_id,
        "alert_id": alert_id,
        "verdict_category": "likely_fp",
        "confidence_score": 0.5,
        "reasoning": "test",
        "contributing_facts": json.dumps([]),
        "evidence_chain": json.dumps({}),
        "model_version": "test",
        "prompt_version": "test",
        "llm_inputs": json.dumps(llm_inputs),
        "llm_raw_output": json.dumps({}),
        "latency_ms": 1200,
        "is_current": True,
    })
    await op_store.link_verdict_to_alert(alert_id, verdict_id)
    return alert_id, verdict_id


# ---------------------------------------------------------------------------
# Protocol conformance
# ---------------------------------------------------------------------------


def test_sqlite_event_store_implements_protocol(store: SQLiteEventStore) -> None:
    assert isinstance(store, EventStore)


# ---------------------------------------------------------------------------
# insert_eve_event / insert_eve_events_batch
# ---------------------------------------------------------------------------


async def test_insert_single_eve_event(store: SQLiteEventStore) -> None:
    event = _make_eve_event()
    await store.insert_eve_event(event)
    events = await store.get_correlated_events(12345)
    assert len(events) == 1
    assert events[0]["event_type"] == "dns"
    assert events[0]["flow_id"] == 12345


async def test_insert_eve_events_batch(store: SQLiteEventStore) -> None:
    events = [_make_eve_event("http", 99), _make_eve_event("tls", 99), _make_eve_event("dns", 99)]
    await store.insert_eve_events_batch(events)
    result = await store.get_correlated_events(99)
    assert len(result) == 3
    types = {e["event_type"] for e in result}
    assert types == {"http", "tls", "dns"}


async def test_insert_eve_events_batch_empty(store: SQLiteEventStore) -> None:
    await store.insert_eve_events_batch([])  # must not raise
    assert await store.get_correlated_events(1) == []


# ---------------------------------------------------------------------------
# insert_alert / get_alert
# ---------------------------------------------------------------------------


async def test_insert_alert_returns_id(store: SQLiteEventStore) -> None:
    alert_id = await store.insert_alert(_make_alert())
    assert isinstance(alert_id, str)
    assert len(alert_id) == 36  # UUID4


async def test_get_alert_round_trip(store: SQLiteEventStore) -> None:
    alert = _make_alert(flow_id=777, src_ip="192.168.1.5", dest_ip="1.2.3.4")
    alert_id = await store.insert_alert(alert)
    row = await store.get_alert(alert_id)
    assert row is not None
    assert row["alert_id"] == alert_id
    assert row["flow_id"] == 777
    assert row["src_ip"] == "192.168.1.5"
    assert row["dst_ip"] == "1.2.3.4"          # stored as dst_ip, mapped from dest_ip
    assert row["signature_id"] == 2000001
    assert row["status"] == "queued"
    assert row["auto_analyzed"] is False


async def test_insert_alert_deferred_status(store: SQLiteEventStore) -> None:
    alert_id = await store.insert_alert(_make_alert(), status="deferred")
    row = await store.get_alert(alert_id)
    assert row is not None
    assert row["status"] == "deferred"


async def test_get_alert_not_found_returns_none(store: SQLiteEventStore) -> None:
    result = await store.get_alert("00000000-0000-0000-0000-000000000000")
    assert result is None


# ---------------------------------------------------------------------------
# get_correlated_events
# ---------------------------------------------------------------------------


async def test_correlated_events_by_flow_id(store: SQLiteEventStore) -> None:
    await store.insert_eve_events_batch([
        _make_eve_event("http", flow_id=1),
        _make_eve_event("dns", flow_id=2),   # different flow — must NOT appear
        _make_eve_event("tls", flow_id=1),
    ])
    result = await store.get_correlated_events(1)
    assert len(result) == 2
    assert all(e["flow_id"] == 1 for e in result)


async def test_correlated_events_time_filter(store: SQLiteEventStore) -> None:
    old_ts = _ts(-7200)   # 2 hours ago
    new_ts = _ts(-60)     # 1 minute ago
    await store.insert_eve_events_batch([
        {**_make_eve_event("dns", 5), "timestamp": old_ts},
        {**_make_eve_event("http", 5), "timestamp": new_ts},
    ])
    cutoff = datetime.now(UTC) - timedelta(hours=1)
    result = await store.get_correlated_events(5, since=cutoff)
    assert len(result) == 1
    assert result[0]["event_type"] == "http"


async def test_correlated_events_ordered_ascending(store: SQLiteEventStore) -> None:
    t1, t2, t3 = _ts(-300), _ts(-200), _ts(-100)
    await store.insert_eve_events_batch([
        {**_make_eve_event("tls", 10), "timestamp": t3},
        {**_make_eve_event("dns", 10), "timestamp": t1},
        {**_make_eve_event("http", 10), "timestamp": t2},
    ])
    result = await store.get_correlated_events(10)
    timestamps = [e["event_timestamp"] for e in result]
    assert timestamps == sorted(timestamps)


# ---------------------------------------------------------------------------
# query_alerts
# ---------------------------------------------------------------------------


async def test_query_alerts_returns_all(store: SQLiteEventStore) -> None:
    await store.insert_alert(_make_alert())
    await store.insert_alert(_make_alert())
    result = await store.query_alerts()
    assert len(result) == 2


async def test_query_alerts_status_filter(store: SQLiteEventStore) -> None:
    await store.insert_alert(_make_alert(), status="queued")
    await store.insert_alert(_make_alert(), status="deferred")
    queued = await store.query_alerts(status="queued")
    deferred = await store.query_alerts(status="deferred")
    assert len(queued) == 1
    assert len(deferred) == 1


async def test_query_alerts_limit_offset(store: SQLiteEventStore) -> None:
    for _ in range(5):
        await store.insert_alert(_make_alert())
    page1 = await store.query_alerts(limit=3, offset=0)
    page2 = await store.query_alerts(limit=3, offset=3)
    assert len(page1) == 3
    assert len(page2) == 2
    ids_p1 = {r["alert_id"] for r in page1}
    ids_p2 = {r["alert_id"] for r in page2}
    assert ids_p1.isdisjoint(ids_p2)


# ---------------------------------------------------------------------------
# count_analyzed_today
# ---------------------------------------------------------------------------


async def test_count_analyzed_today_excludes_deferred(store: SQLiteEventStore) -> None:
    await store.insert_alert(_make_alert(), status="queued")
    await store.insert_alert(_make_alert(), status="queued")
    await store.insert_alert(_make_alert(), status="deferred")
    count = await store.count_analyzed_today()
    assert count == 2


async def test_count_analyzed_today_initial_zero(store: SQLiteEventStore) -> None:
    assert await store.count_analyzed_today() == 0


# ---------------------------------------------------------------------------
# update_alert_status
# ---------------------------------------------------------------------------


async def test_update_alert_status(store: SQLiteEventStore) -> None:
    alert_id = await store.insert_alert(_make_alert())
    await store.update_alert_status(alert_id, "analyzed")
    row = await store.get_alert(alert_id)
    assert row is not None
    assert row["status"] == "analyzed"


# ---------------------------------------------------------------------------
# delete_expired_eve_events
# ---------------------------------------------------------------------------


async def test_delete_expired_eve_events(store: SQLiteEventStore) -> None:
    old_ts = _ts(-8 * 86400)   # 8 days ago — beyond 7-day retention
    new_ts = _ts(-86400)        # 1 day ago — within retention
    await store.insert_eve_events_batch([
        {**_make_eve_event("dns", 1), "timestamp": old_ts},
        {**_make_eve_event("http", 2), "timestamp": new_ts},
    ])
    deleted = await store.delete_expired_eve_events(retention_days=7)
    assert deleted == 1
    assert await store.get_correlated_events(1) == []   # old one gone
    assert len(await store.get_correlated_events(2)) == 1  # new one kept


async def test_delete_expired_returns_zero_when_nothing_to_delete(store: SQLiteEventStore) -> None:
    await store.insert_eve_event(_make_eve_event())  # recent
    deleted = await store.delete_expired_eve_events(retention_days=7)
    assert deleted == 0


# ---------------------------------------------------------------------------
# find_recent_verdict_for_group — ADR-022 DECIDE 1 (one hop only)
# ---------------------------------------------------------------------------


async def test_find_recent_verdict_for_group_skips_inherited_candidate(
    store: SQLiteEventStore, op_store: SQLiteOperationalStore,
) -> None:
    """An inherited nearest-candidate is skipped in favor of an earlier produced
    verdict within the same window — reaching past it is still one hop, since the
    result points directly at a produced verdict, not at the inherited one."""
    _, produced_verdict_id = await _seed_analyzed_alert(
        store, op_store,
        llm_inputs={"prompt": "...", "output_schema": {}},
        ingest_timestamp=_ts(-1800),  # 30 min ago
    )
    await _seed_analyzed_alert(
        store, op_store,
        llm_inputs={"inherited_from": produced_verdict_id},
        ingest_timestamp=_ts(-600),  # 10 min ago — the nearest group member
    )

    result = await store.find_recent_verdict_for_group(2000001, "10.0.0.1", "8.8.8.8", _ts())

    assert result == produced_verdict_id


async def test_find_recent_verdict_for_group_none_when_no_produced_source_in_window(
    store: SQLiteEventStore, op_store: SQLiteOperationalStore,
) -> None:
    """None only when no produced verdict exists in the window at all — not merely
    when the nearest candidate happens to be inherited."""
    await _seed_analyzed_alert(
        store, op_store,
        llm_inputs={"inherited_from": str(uuid.uuid4())},
        ingest_timestamp=_ts(-600),
    )

    result = await store.find_recent_verdict_for_group(2000001, "10.0.0.1", "8.8.8.8", _ts())

    assert result is None


async def test_find_recent_verdict_for_group_still_finds_produced_source(
    store: SQLiteEventStore, op_store: SQLiteOperationalStore,
) -> None:
    """Baseline: a produced source within the window is still found (no regression)."""
    _, produced_verdict_id = await _seed_analyzed_alert(
        store, op_store,
        llm_inputs={"prompt": "...", "output_schema": {}},
        ingest_timestamp=_ts(-600),
    )

    result = await store.find_recent_verdict_for_group(2000001, "10.0.0.1", "8.8.8.8", _ts())

    assert result == produced_verdict_id


# ---------------------------------------------------------------------------
# find_recent_verdict_for_group — ADR-022 Decision (window anchored to the
# candidate alert's own ingest_timestamp, not to datetime.now(UTC))
# ---------------------------------------------------------------------------


async def test_find_recent_verdict_for_group_anchors_to_candidate_not_now(
    store: SQLiteEventStore, op_store: SQLiteOperationalStore,
) -> None:
    """A and B are both ingested together, well outside a real 1-hour window
    measured from the actual current time -- this is what a slow host or a
    processing backlog looks like. Anchored to B's own ingest_timestamp
    (also T0), A is well within window_hours of B regardless of how much
    wall-clock time has passed since either arrived.

    This is the regression case for the now()-anchored bug: run against the
    pre-fix `since = datetime.now(UTC) - timedelta(hours=window_hours)` code,
    this returns None, because `since` sits about an hour ahead of T0 and
    Alert.ingest_timestamp (T0) < since. Confirmed by temporarily reverting
    the anchor and re-running this test -- it fails as expected (None, not
    A's verdict_id) against the pre-fix code.
    """
    t0 = _ts(-7200)  # both A and B ingested 2h before the real now()
    _, produced_verdict_id = await _seed_analyzed_alert(
        store, op_store,
        llm_inputs={"prompt": "...", "output_schema": {}},
        ingest_timestamp=t0,
    )

    result = await store.find_recent_verdict_for_group(2000001, "10.0.0.1", "8.8.8.8", t0)

    assert result == produced_verdict_id


async def test_find_recent_verdict_for_group_stale_source_rejected_by_real_gap(
    store: SQLiteEventStore, op_store: SQLiteOperationalStore,
) -> None:
    """Guards against overshooting into inheriting from anything ever, once the
    now()-anchored bug is fixed. Varies the true ingest-to-ingest gap between A
    and the candidate directly -- both timestamps are real, fixed values, with
    no reliance on how long ago either sits relative to the actual now() -- so
    this independently exercises genuine staleness, which the pre-fix code
    conflated with processing delay into a single now() reference."""
    t0 = _ts(-3 * 3600)  # A ingested 3h before the real now()
    await _seed_analyzed_alert(
        store, op_store,
        llm_inputs={"prompt": "...", "output_schema": {}},
        ingest_timestamp=t0,
    )
    candidate_ts = _ts(-1 * 3600)  # candidate's own ingest_timestamp: 2h after A

    result = await store.find_recent_verdict_for_group(
        2000001, "10.0.0.1", "8.8.8.8", candidate_ts, window_hours=1,
    )

    assert result is None


async def test_find_recent_verdict_for_group_excludes_source_after_candidate(
    store: SQLiteEventStore, op_store: SQLiteOperationalStore,
) -> None:
    """ADR-022 implementation clarification, 2026-08-27: the window is
    symmetric. A produced verdict ingested AFTER the candidate -- even well
    inside window_hours -- is not a valid inheritance source. "Arrived within
    an hour of each other" excludes a later arrival exactly as much as an
    earlier one outside the window.

    Confirmed failing against the pre-bound code (the query as of ADR-023's
    FIFO commit, before this test's own commit added the upper bound): with
    no upper bound, `Alert.ingest_timestamp >= since` alone is satisfied by
    the later-arriving source, `ORDER BY ingest_timestamp DESC LIMIT 1` picks
    it as the newest eligible row, and the pre-bound code returns its
    verdict_id instead of None.
    """
    candidate_ts = _ts(-1800)  # candidate ingested 30 min ago
    _, produced_verdict_id = await _seed_analyzed_alert(
        store, op_store,
        llm_inputs={"prompt": "...", "output_schema": {}},
        ingest_timestamp=_ts(-600),  # source ingested 10 min ago -- AFTER the
                                      # candidate, still inside the 1h window
    )

    result = await store.find_recent_verdict_for_group(
        2000001, "10.0.0.1", "8.8.8.8", candidate_ts,
    )

    assert result is None
    assert produced_verdict_id is not None  # sanity: the source really was seeded
