# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Context variable helpers for per-alert and per-request log binding.

structlog uses Python's contextvars under the hood, so bindings are
async-safe: each asyncio Task has its own copy of the context.

Standard bound keys across the codebase:
  alert_id   — Suricata EVE alert being processed (str)
  trace_id   — random UUID per alert lifecycle (str)
  sensor_id  — always 1 in v0.1 (int)
  purpose    — HTTP client purpose tag, e.g. "virustotal" (str)
"""
from __future__ import annotations

import uuid

from structlog.contextvars import bind_contextvars, clear_contextvars

_SENSOR_ID = 1  # single-sensor in v0.1; multi-sensor is the v1 commercial conversion event


def bind_alert_context(alert_id: str, trace_id: str | None = None) -> str:
    """Bind alert-scoped context variables and return the trace_id used.

    Call once at the start of each alert's triage lifecycle. Pair with
    clear_alert_context() when processing completes.
    """
    tid = trace_id or str(uuid.uuid4())
    bind_contextvars(alert_id=alert_id, trace_id=tid, sensor_id=_SENSOR_ID)
    return tid


def bind_http_context(purpose: str) -> None:
    """Bind the HTTP purpose tag so all log lines in this request carry it."""
    bind_contextvars(purpose=purpose)


def clear_alert_context() -> None:
    """Clear all bound context variables. Call after alert processing completes."""
    clear_contextvars()
