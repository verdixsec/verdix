# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Tests for IngestionStatus (ADR-019)."""
from __future__ import annotations

from src.ingestion.status import IngestionStatus


def _fail(status: IngestionStatus, n: int) -> list[bool]:
    return [status.record_failure(Exception(f"boom-{i}")) for i in range(n)]


# ---------------------------------------------------------------------------
# Red/green transitions
# ---------------------------------------------------------------------------


def test_four_failures_stay_green() -> None:
    status = IngestionStatus()
    transitions = _fail(status, 4)
    assert status.state == "green"
    assert status.consecutive_failures == 4
    assert transitions == [False, False, False, False]


def test_fifth_failure_flips_red() -> None:
    status = IngestionStatus()
    transitions = _fail(status, 5)
    assert status.state == "red"
    assert status.consecutive_failures == 5
    assert transitions == [False, False, False, False, True]
    assert status.state_changed_at is not None


def test_failures_past_five_do_not_re_transition() -> None:
    status = IngestionStatus()
    _fail(status, 5)
    transitions = _fail(status, 3)  # 6th, 7th, 8th
    assert transitions == [False, False, False]
    assert status.state == "red"
    assert status.consecutive_failures == 8


def test_success_after_red_returns_green_and_resets_counter() -> None:
    status = IngestionStatus()
    _fail(status, 5)
    transitioned = status.record_success()
    assert transitioned is True
    assert status.state == "green"
    assert status.consecutive_failures == 0
    assert status.last_error is None


def test_success_while_already_green_does_not_transition() -> None:
    status = IngestionStatus()
    assert status.record_success() is False
    assert status.state == "green"


def test_last_error_reflects_most_recent_exception() -> None:
    status = IngestionStatus()
    status.record_failure(PermissionError("nope"))
    assert status.last_error == "nope"


def test_record_blocked_sets_red_and_reason() -> None:
    status = IngestionStatus()
    status.record_blocked("suricata.yaml unreadable")
    assert status.state == "red"
    assert status.blocked_reason == "suricata.yaml unreadable"
    assert status.state_changed_at is not None


# ---------------------------------------------------------------------------
# Retry interval schedule
# ---------------------------------------------------------------------------


def test_retry_interval_below_threshold_uses_poll_interval() -> None:
    status = IngestionStatus(poll_interval_ms=500)
    assert status.retry_interval_s == 0.5
    _fail(status, 4)
    assert status.retry_interval_s == 0.5


def test_retry_interval_widens_at_thresholds() -> None:
    status = IngestionStatus(poll_interval_ms=500)
    _fail(status, 5)
    assert status.retry_interval_s == 60.0
    _fail(status, 2)  # 7
    assert status.retry_interval_s == 60.0
    _fail(status, 1)  # 8
    assert status.retry_interval_s == 300.0
    _fail(status, 2)  # 10
    assert status.retry_interval_s == 300.0
    _fail(status, 1)  # 11
    assert status.retry_interval_s == 600.0


def test_retry_interval_stays_at_600_indefinitely() -> None:
    status = IngestionStatus()
    _fail(status, 50)
    assert status.retry_interval_s == 600.0
    assert status.state == "red"


# ---------------------------------------------------------------------------
# to_dict
# ---------------------------------------------------------------------------


def test_to_dict_shape() -> None:
    status = IngestionStatus()
    status.record_failure(Exception("x"))
    d = status.to_dict()
    assert set(d.keys()) == {
        "state", "consecutive_failures", "last_error",
        "last_success_at", "state_changed_at", "blocked_reason",
    }
    assert d["state"] == "green"
    assert d["consecutive_failures"] == 1
