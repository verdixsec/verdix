# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Tests for _build_queue_rows()'s verdict-bubbling display logic.

Uses a real in-memory SQLite OperationalStore, matching the convention in
src/triage/test_worker.py. asyncio_mode = "auto" — no @pytest.mark.asyncio needed.
"""
from __future__ import annotations

import json
import uuid

import pytest

from src.infra.db.operational_store import SQLiteOperationalStore
from src.infra.db.session import close_db, init_db
from src.web.routes.queue_routes import _build_queue_rows


@pytest.fixture(autouse=True)
async def fresh_db() -> None:
    await init_db("sqlite+aiosqlite:///:memory:")
    yield
    await close_db()


@pytest.fixture
def op_store() -> SQLiteOperationalStore:
    return SQLiteOperationalStore()


def _alert(alert_id: str, verdict_id: str | None, ingest_timestamp: str) -> dict:
    return {
        "alert_id": alert_id,
        "verdict_id": verdict_id,
        "signature_id": 2027868,
        "signature_msg": "ET INFO Observed DNS Query to .work TLD",
        "signature_severity": 2,
        "src_ip": "10.6.30.101",
        "dst_ip": "10.6.30.1",
        "src_port": 5353,
        "dst_port": 53,
        "proto": "UDP",
        "app_proto": "dns",
        "event_timestamp": "2026-08-26T18:00:00Z",
        "ingest_timestamp": ingest_timestamp,
        "status": "analyzed" if verdict_id else "queued",
        "disposition_id": None,
        "attacker_role": None,
        "victim_role": None,
    }


async def _record_verdict(
    op_store: SQLiteOperationalStore, alert_id: str, category: str, confidence: float
) -> str:
    verdict_id = str(uuid.uuid4())
    await op_store.record_verdict({
        "verdict_id": verdict_id,
        "alert_id": alert_id,
        "verdict_category": category,
        "confidence_score": confidence,
        "reasoning": "test",
        "contributing_facts": json.dumps([]),
        "evidence_chain": json.dumps({}),
        "model_version": "test",
        "prompt_version": "test",
        "llm_inputs": json.dumps({}),
        "llm_raw_output": json.dumps({}),
        "latency_ms": 100,
        "is_current": True,
    })
    return verdict_id


async def test_homogeneous_group_bubbles_single_verdict(
    op_store: SQLiteOperationalStore,
):
    """Members agreeing on verdict_category render as today: one badge, no mixed flag."""
    v1 = await _record_verdict(op_store, "a1", "likely_fp", 0.40)
    v2 = await _record_verdict(op_store, "a2", "likely_fp", 0.40)
    alerts = [
        _alert("a1", v1, "2026-08-26T18:00:01Z"),
        _alert("a2", v2, "2026-08-26T18:00:02Z"),
    ]

    rows = await _build_queue_rows(alerts, op_store)

    assert len(rows) == 1
    row = rows[0]
    assert row["count"] == 2
    assert row["verdict_mixed"] is False
    assert row["verdict_breakdown"] == []
    assert row["verdict_category"] == "likely_fp"
    assert row["confidence_score"] == 0.40


async def test_heterogeneous_group_does_not_bubble_single_verdict(
    op_store: SQLiteOperationalStore,
):
    """Members disagreeing on verdict_category must not present one as the group's verdict."""
    v1 = await _record_verdict(op_store, "a1", "likely_fp", 0.40)
    v2 = await _record_verdict(op_store, "a2", "suspicious_investigate", 0.65)
    v3 = await _record_verdict(op_store, "a3", "likely_fp", 0.40)
    alerts = [
        _alert("a1", v1, "2026-08-26T18:00:01Z"),
        _alert("a2", v2, "2026-08-26T18:00:02Z"),
        _alert("a3", v3, "2026-08-26T18:00:03Z"),
    ]

    rows = await _build_queue_rows(alerts, op_store)

    assert len(rows) == 1
    row = rows[0]
    assert row["count"] == 3
    assert row["verdict_mixed"] is True
    # No single category or confidence stands in for the group.
    assert row["verdict_category"] is None
    assert row["confidence_score"] is None
    assert row["verdict_breakdown"] == [("FP", 2), ("Investigate", 1)]


async def test_unanalyzed_group_is_not_mixed(op_store: SQLiteOperationalStore):
    """A group with zero analyzed members is pending, not mixed."""
    alerts = [
        _alert("a1", None, "2026-08-26T18:00:01Z"),
        _alert("a2", None, "2026-08-26T18:00:02Z"),
    ]

    rows = await _build_queue_rows(alerts, op_store)

    assert len(rows) == 1
    row = rows[0]
    assert row["verdict_mixed"] is False
    assert row["verdict_category"] is None
