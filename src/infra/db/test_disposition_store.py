# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Tests for SQLiteDispositionStore.

Each test gets a fresh in-memory SQLite database via the autouse fixture.
asyncio_mode = "auto" is set in pyproject.toml — no @pytest.mark.asyncio needed.
"""
from __future__ import annotations

import uuid

import pytest

from src.infra.db.disposition_store import SQLiteDispositionStore
from src.infra.db.session import close_db, init_db
from src.interfaces.disposition_store import DispositionStore


@pytest.fixture(autouse=True)
async def fresh_db() -> None:
    await init_db("sqlite+aiosqlite:///:memory:")
    yield
    await close_db()


@pytest.fixture
def store() -> SQLiteDispositionStore:
    return SQLiteDispositionStore()


# ---------------------------------------------------------------------------
# Interface conformance
# ---------------------------------------------------------------------------


def test_implements_protocol(store: SQLiteDispositionStore) -> None:
    assert isinstance(store, DispositionStore)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_disposition(
    alert_id: str,
    action: str = "accept",
    override_category: str | None = None,
    reason: str | None = None,
) -> dict:
    return {
        "alert_id": alert_id,
        "analyst_user_id": "admin-user-id",
        "disposition_action": action,
        "override_category": override_category,
        "override_reason_freetext": reason,
    }


# ---------------------------------------------------------------------------
# record_disposition
# ---------------------------------------------------------------------------


async def test_record_returns_disposition_id(store: SQLiteDispositionStore) -> None:
    alert_id = str(uuid.uuid4())
    disp_id = await store.record_disposition(_make_disposition(alert_id))
    assert isinstance(disp_id, str)
    assert len(disp_id) == 36  # UUID format


async def test_record_uses_provided_id(store: SQLiteDispositionStore) -> None:
    alert_id = str(uuid.uuid4())
    custom_id = str(uuid.uuid4())
    disp = _make_disposition(alert_id)
    disp["disposition_id"] = custom_id
    returned_id = await store.record_disposition(disp)
    assert returned_id == custom_id


async def test_record_accept_disposition(store: SQLiteDispositionStore) -> None:
    alert_id = str(uuid.uuid4())
    disp_id = await store.record_disposition(_make_disposition(alert_id, action="accept"))
    fetched = await store.get_disposition(disp_id)
    assert fetched is not None
    assert fetched["disposition_action"] == "accept"
    assert fetched["override_category"] is None
    assert fetched["schema_version"] == 1


async def test_record_override_disposition(store: SQLiteDispositionStore) -> None:
    alert_id = str(uuid.uuid4())
    disp_id = await store.record_disposition(
        _make_disposition(
            alert_id,
            action="override",
            override_category="likely_tp",
            reason="CnC callback confirmed via threat intel",
        )
    )
    fetched = await store.get_disposition(disp_id)
    assert fetched["disposition_action"] == "override"
    assert fetched["override_category"] == "likely_tp"
    assert "threat intel" in fetched["override_reason_freetext"]


# ---------------------------------------------------------------------------
# get_disposition
# ---------------------------------------------------------------------------


async def test_get_disposition_missing(store: SQLiteDispositionStore) -> None:
    assert await store.get_disposition(str(uuid.uuid4())) is None


# ---------------------------------------------------------------------------
# get_latest_disposition
# ---------------------------------------------------------------------------


async def test_get_latest_disposition_none_when_empty(store: SQLiteDispositionStore) -> None:
    assert await store.get_latest_disposition(str(uuid.uuid4())) is None


async def test_get_latest_disposition_returns_most_recent(store: SQLiteDispositionStore) -> None:
    alert_id = str(uuid.uuid4())
    await store.record_disposition(_make_disposition(alert_id, action="accept"))
    disp_id_2 = await store.record_disposition(
        _make_disposition(alert_id, action="override", override_category="likely_tp")
    )
    latest = await store.get_latest_disposition(alert_id)
    assert latest is not None
    assert latest["disposition_id"] == disp_id_2
    assert latest["disposition_action"] == "override"


# ---------------------------------------------------------------------------
# get_dispositions_for_alert
# ---------------------------------------------------------------------------


async def test_get_dispositions_empty(store: SQLiteDispositionStore) -> None:
    assert await store.get_dispositions_for_alert(str(uuid.uuid4())) == []


async def test_get_dispositions_ordered_desc(store: SQLiteDispositionStore) -> None:
    alert_id = str(uuid.uuid4())
    id1 = await store.record_disposition(_make_disposition(alert_id, action="accept"))
    id2 = await store.record_disposition(
        _make_disposition(alert_id, action="override", override_category="likely_fp")
    )
    all_disps = await store.get_dispositions_for_alert(alert_id)
    assert len(all_disps) == 2
    assert all_disps[0]["disposition_id"] == id2  # most recent first
    assert all_disps[1]["disposition_id"] == id1


async def test_get_dispositions_isolated_by_alert(store: SQLiteDispositionStore) -> None:
    alert_a = str(uuid.uuid4())
    alert_b = str(uuid.uuid4())
    await store.record_disposition(_make_disposition(alert_a))
    await store.record_disposition(_make_disposition(alert_b))

    assert len(await store.get_dispositions_for_alert(alert_a)) == 1
    assert len(await store.get_dispositions_for_alert(alert_b)) == 1


async def test_verdict_id_stored_when_provided(store: SQLiteDispositionStore) -> None:
    alert_id = str(uuid.uuid4())
    verdict_id = str(uuid.uuid4())
    disp = _make_disposition(alert_id)
    disp["verdict_id"] = verdict_id
    disp_id = await store.record_disposition(disp)
    fetched = await store.get_disposition(disp_id)
    assert fetched["verdict_id"] == verdict_id
