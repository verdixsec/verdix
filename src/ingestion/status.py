# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Live ingestion health, in-memory only (ADR-019).

Tracks the eve.json tailer's read health as a small state machine: green while
reads succeed or fail only transiently, red after five consecutive failures.
Transition logic (when to flip color, how far to widen the retry interval)
lives here rather than in the tailer, so the tailer only needs to report
individual successes and failures.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

_RED_THRESHOLD = 5


class IngestionStatus:
    """Tracks eve.json tailer health and derives its retry interval.

    Args:
        poll_interval_ms: Normal (healthy) poll interval, used as the retry
            interval below the red threshold.
    """

    def __init__(self, poll_interval_ms: int = 500) -> None:
        self._poll_interval_s = poll_interval_ms / 1000.0
        self.state: str = "green"
        self.consecutive_failures: int = 0
        self.last_error: str | None = None
        self.last_success_at: datetime | None = None
        self.state_changed_at: datetime | None = None
        self.blocked_reason: str | None = None

    def record_success(self) -> bool:
        """Reset the failure counter and record the read. Returns True if
        this success transitioned state from red to green."""
        transitioned = self.state == "red"
        self.consecutive_failures = 0
        self.last_success_at = datetime.now(UTC)
        self.last_error = None
        if transitioned:
            self.state = "green"
            self.state_changed_at = self.last_success_at
        return transitioned

    def record_failure(self, exc: Exception) -> bool:
        """Count a failed read. Returns True if this failure transitioned
        state from green to red (i.e. the counter just reached the
        red threshold)."""
        self.consecutive_failures += 1
        self.last_error = str(exc)
        transitioned = False
        if self.consecutive_failures >= _RED_THRESHOLD and self.state != "red":
            self.state = "red"
            self.state_changed_at = datetime.now(UTC)
            transitioned = True
        return transitioned

    def record_blocked(self, reason: str) -> None:
        """Mark ingestion as blocked at startup (e.g. suricata.yaml unreadable)."""
        self.state = "red"
        self.blocked_reason = reason
        self.state_changed_at = datetime.now(UTC)

    @property
    def retry_interval_s(self) -> float:
        """Poll/retry interval derived from the current failure count."""
        n = self.consecutive_failures
        if n < _RED_THRESHOLD:
            return self._poll_interval_s
        if n <= 7:
            return 60.0
        if n <= 10:
            return 300.0
        return 600.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "consecutive_failures": self.consecutive_failures,
            "last_error": self.last_error,
            "last_success_at": (
                self.last_success_at.isoformat() if self.last_success_at else None
            ),
            "state_changed_at": (
                self.state_changed_at.isoformat() if self.state_changed_at else None
            ),
            "blocked_reason": self.blocked_reason,
        }
