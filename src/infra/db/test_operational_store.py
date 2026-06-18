# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Tests for SQLiteOperationalStore.

Each test gets a fresh in-memory SQLite database via the autouse fixture.
asyncio_mode = "auto" is set in pyproject.toml — no @pytest.mark.asyncio needed.
"""
from __future__ import annotations

import json
import uuid

import pytest

from src.infra.db.operational_store import SQLiteOperationalStore
from src.infra.db.session import close_db, init_db
from src.interfaces.operational_store import OperationalStore


@pytest.fixture(autouse=True)
async def fresh_db() -> None:
    await init_db("sqlite+aiosqlite:///:memory:")
    yield
    await close_db()


@pytest.fixture
def store() -> SQLiteOperationalStore:
    return SQLiteOperationalStore()


# ---------------------------------------------------------------------------
# Interface conformance
# ---------------------------------------------------------------------------


def test_implements_protocol(store: SQLiteOperationalStore) -> None:
    assert isinstance(store, OperationalStore)


# ---------------------------------------------------------------------------
# System config
# ---------------------------------------------------------------------------


async def test_get_config_missing(store: SQLiteOperationalStore) -> None:
    assert await store.get_config("no_such_key") is None


async def test_set_and_get_config(store: SQLiteOperationalStore) -> None:
    await store.set_config("eula_accepted", "true")
    assert await store.get_config("eula_accepted") == "true"


async def test_set_config_upserts(store: SQLiteOperationalStore) -> None:
    await store.set_config("k", "v1")
    await store.set_config("k", "v2")
    assert await store.get_config("k") == "v2"


async def test_multiple_config_keys(store: SQLiteOperationalStore) -> None:
    await store.set_config("eula_accepted", "true")
    await store.set_config("setup_complete", "false")
    assert await store.get_config("eula_accepted") == "true"
    assert await store.get_config("setup_complete") == "false"


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


async def test_get_user_by_username_missing(store: SQLiteOperationalStore) -> None:
    assert await store.get_user_by_username("nobody") is None


async def test_ensure_admin_user_creates(store: SQLiteOperationalStore) -> None:
    uid = str(uuid.uuid4())
    await store.ensure_admin_user(uid)
    user = await store.get_user_by_username("admin")
    assert user is not None
    assert user["user_id"] == uid
    assert user["role"] == "admin"
    assert user["password_hash"] is None


async def test_ensure_admin_user_idempotent(store: SQLiteOperationalStore) -> None:
    uid = str(uuid.uuid4())
    await store.ensure_admin_user(uid)
    await store.ensure_admin_user(str(uuid.uuid4()))  # second call with different id
    user = await store.get_user_by_username("admin")
    assert user is not None
    assert user["user_id"] == uid  # original id preserved


async def test_update_last_login(store: SQLiteOperationalStore) -> None:
    uid = str(uuid.uuid4())
    await store.ensure_admin_user(uid)
    user_before = await store.get_user_by_username("admin")
    assert user_before["last_login_at"] is None

    await store.update_last_login(uid)
    user_after = await store.get_user_by_username("admin")
    assert user_after["last_login_at"] is not None


# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------


def _make_verdict(alert_id: str, *, is_current: bool = True) -> dict:
    return {
        "verdict_id": str(uuid.uuid4()),
        "alert_id": alert_id,
        "verdict_category": "likely_fp",
        "confidence_score": 0.85,
        "reasoning": "The signature fires on normal curl traffic.",
        "contributing_facts": json.dumps(["User-Agent matches curl", "Destination is Google DNS"]),
        "evidence_chain": json.dumps({"enrichment": [], "eve_events": []}),
        "model_version": "gemma4:e4b-it-q8_0",
        "prompt_version": "verdict_v1",
        "llm_inputs": json.dumps({"prompt": "..."}),
        "llm_raw_output": json.dumps({"verdict_category": "likely_fp"}),
        "latency_ms": 12345,
        "is_current": is_current,
    }


async def test_record_and_get_verdict(store: SQLiteOperationalStore) -> None:
    alert_id = str(uuid.uuid4())
    v = _make_verdict(alert_id)
    await store.record_verdict(v)
    fetched = await store.get_verdict(v["verdict_id"])
    assert fetched is not None
    assert fetched["verdict_category"] == "likely_fp"
    assert fetched["alert_id"] == alert_id


async def test_get_verdict_missing(store: SQLiteOperationalStore) -> None:
    assert await store.get_verdict(str(uuid.uuid4())) is None


async def test_get_current_verdict_for_alert(store: SQLiteOperationalStore) -> None:
    alert_id = str(uuid.uuid4())
    v = _make_verdict(alert_id)
    await store.record_verdict(v)
    current = await store.get_current_verdict_for_alert(alert_id)
    assert current is not None
    assert current["verdict_id"] == v["verdict_id"]


async def test_get_current_verdict_none_when_not_analyzed(store: SQLiteOperationalStore) -> None:
    assert await store.get_current_verdict_for_alert(str(uuid.uuid4())) is None


async def test_mark_previous_verdicts_superseded(store: SQLiteOperationalStore) -> None:
    alert_id = str(uuid.uuid4())
    v1 = _make_verdict(alert_id)
    await store.record_verdict(v1)
    await store.mark_previous_verdicts_superseded(alert_id)

    old = await store.get_verdict(v1["verdict_id"])
    assert old["is_current"] is False

    v2 = _make_verdict(alert_id)
    await store.record_verdict(v2)
    current = await store.get_current_verdict_for_alert(alert_id)
    assert current["verdict_id"] == v2["verdict_id"]


async def test_record_verdict_auto_generates_ids(store: SQLiteOperationalStore) -> None:
    alert_id = str(uuid.uuid4())
    v = _make_verdict(alert_id)
    del v["verdict_id"]  # let the store generate it
    await store.record_verdict(v)
    # Should not raise; at least one verdict exists for the alert
    current = await store.get_current_verdict_for_alert(alert_id)
    assert current is not None


# ---------------------------------------------------------------------------
# Alert FK updates
# ---------------------------------------------------------------------------


async def test_link_verdict_to_alert(store: SQLiteOperationalStore) -> None:
    from src.infra.db.event_store import SQLiteEventStore

    eve_store = SQLiteEventStore()
    alert_dict = {
        "timestamp": "2026-01-01T00:00:00Z",
        "flow_id": 1,
        "event_type": "alert",
        "src_ip": "10.0.0.1",
        "src_port": 1234,
        "dest_ip": "8.8.8.8",
        "dest_port": 80,
        "proto": "TCP",
        "alert": {"signature_id": 1, "signature": "ET TEST", "severity": 2},
    }
    alert_id = await eve_store.insert_alert(alert_dict)
    verdict_id = str(uuid.uuid4())

    await store.link_verdict_to_alert(alert_id, verdict_id)

    fetched = await eve_store.get_alert(alert_id)
    assert fetched["verdict_id"] == verdict_id
    assert fetched["status"] == "analyzed"
    assert fetched["auto_analyzed"] is True


async def test_link_disposition_to_alert(store: SQLiteOperationalStore) -> None:
    from src.infra.db.event_store import SQLiteEventStore

    eve_store = SQLiteEventStore()
    alert_dict = {
        "timestamp": "2026-01-01T00:00:00Z",
        "flow_id": 2,
        "event_type": "alert",
        "src_ip": "10.0.0.2",
        "src_port": 5678,
        "dest_ip": "1.1.1.1",
        "dest_port": 443,
        "proto": "TCP",
        "alert": {"signature_id": 2, "signature": "ET TEST2", "severity": 1},
    }
    alert_id = await eve_store.insert_alert(alert_dict)
    disp_id = str(uuid.uuid4())

    await store.link_disposition_to_alert(alert_id, disp_id)

    fetched = await eve_store.get_alert(alert_id)
    assert fetched["disposition_id"] == disp_id
