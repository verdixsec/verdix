# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Tests for structlog setup and context binding."""
from __future__ import annotations

import json

import pytest
import structlog
from structlog.contextvars import get_contextvars
from structlog.testing import capture_logs

from src.infra.logging.context import (
    bind_alert_context,
    bind_http_context,
    clear_alert_context,
)
from src.infra.logging.setup import configure_logging


@pytest.fixture(autouse=True)
def _clear_context_after_each_test() -> None:
    """Ensure no context leaks between tests."""
    yield
    clear_alert_context()


# ---------------------------------------------------------------------------
# configure_logging
# ---------------------------------------------------------------------------


def test_configure_logging_does_not_raise() -> None:
    configure_logging("INFO")


def test_configure_logging_debug_does_not_raise() -> None:
    configure_logging("DEBUG")


# ---------------------------------------------------------------------------
# bind_alert_context — verifies the right keys land in the contextvars store
# (capture_logs() bypasses merge_contextvars, so we read contextvars directly)
# ---------------------------------------------------------------------------


def test_bind_alert_context_returns_trace_id() -> None:
    tid = bind_alert_context("test-alert-001")
    assert isinstance(tid, str) and len(tid) > 0


def test_bind_alert_context_accepts_explicit_trace_id() -> None:
    tid = bind_alert_context("test-alert-002", trace_id="fixed-tid-xyz")
    assert tid == "fixed-tid-xyz"


def test_bind_alert_context_sets_expected_keys() -> None:
    bind_alert_context("test-alert-003", trace_id="tid-003")
    ctx = get_contextvars()
    assert ctx["alert_id"] == "test-alert-003"
    assert ctx["trace_id"] == "tid-003"
    assert ctx["sensor_id"] == 1


def test_sensor_id_is_always_1() -> None:
    bind_alert_context("test-alert-004")
    ctx = get_contextvars()
    assert ctx["sensor_id"] == 1


# ---------------------------------------------------------------------------
# bind_http_context
# ---------------------------------------------------------------------------


def test_http_context_sets_purpose_key() -> None:
    bind_http_context("virustotal")
    ctx = get_contextvars()
    assert ctx["purpose"] == "virustotal"


# ---------------------------------------------------------------------------
# clear_alert_context
# ---------------------------------------------------------------------------


def test_clear_alert_context_removes_bindings() -> None:
    bind_alert_context("test-alert-005")
    clear_alert_context()
    assert get_contextvars() == {}


def test_clear_alert_context_is_safe_when_nothing_bound() -> None:
    clear_alert_context()  # must not raise


# ---------------------------------------------------------------------------
# capture_logs — verifies log events carry their local key-value pairs
# ---------------------------------------------------------------------------


def test_local_event_keys_appear_in_captured_logs() -> None:
    with capture_logs() as logs:
        structlog.get_logger().info("processing_alert", step="enrichment", alert_id="x-001")

    assert logs[0]["event"] == "processing_alert"
    assert logs[0]["step"] == "enrichment"
    assert logs[0]["alert_id"] == "x-001"


# ---------------------------------------------------------------------------
# JSON output (integration: verifies the full processor chain end-to-end)
# ---------------------------------------------------------------------------


def test_configure_logging_produces_valid_json(capsys: pytest.CaptureFixture[str]) -> None:
    """Verify the full processor chain emits parseable JSON with expected keys."""
    structlog.reset_defaults()
    configure_logging("DEBUG")

    structlog.get_logger().info("json_smoke_test", check="passed")

    captured = capsys.readouterr()
    lines = [line for line in captured.out.strip().split("\n") if line.strip()]
    assert lines, "Expected at least one log line on stdout"

    parsed = json.loads(lines[-1])
    assert parsed["event"] == "json_smoke_test"
    assert parsed["check"] == "passed"
    assert parsed["level"] == "info"
    assert "timestamp" in parsed
