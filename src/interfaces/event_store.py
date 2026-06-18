# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""EventStore interface — abstract over OLAP-shaped EVE event storage.

Concrete implementations:
  v0.1  src/infra/db/event_store.py  — SQLite via SQLAlchemy async
  v1.x  DuckDB or ClickHouse (swap target for high-volume deployments)

Application code must import this Protocol, never the concrete class.
Concrete instances arrive via dependency injection.
"""
from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from src.domain.role_assignment.models import RoleAssignment


@runtime_checkable
class EventStore(Protocol):
    """Storage interface for raw EVE events and alerts.

    Two retention tiers (ADR-003):
      - eve_events table: 7 days (VX_EVE_CONTEXT_RETENTION_DAYS)
      - alerts table: indefinite (disposition training corpus)
    """

    async def insert_eve_event(self, event: dict[str, Any]) -> None:
        """Persist a single raw EVE event to eve_events.

        Args:
            event: Parsed EVE JSON dict. Must contain at minimum:
                   flow_id (int), event_type (str), timestamp (str).
                   The full raw dict is stored as-is for replay.
        """
        ...

    async def insert_eve_events_batch(self, events: list[dict[str, Any]]) -> None:
        """Persist a batch of raw EVE events in a single transaction.

        Preferred over repeated insert_eve_event calls for throughput.
        """
        ...

    async def insert_alert(self, alert: dict[str, Any], *, status: str = "queued") -> str:
        """Persist an alert event and return the generated alert_id.

        Args:
            alert:  Parsed EVE alert JSON dict. Must be event_type="alert".
            status: Initial queue status. Dispatcher passes 'deferred' when the
                    daily cap (VX_TRIAGE_DAILY_CAP) has been reached; defaults
                    to 'queued' for normal insertion.

        Returns:
            alert_id: The locally-generated UUID for this alert row.
        """
        ...

    async def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        """Retrieve a single alert by its local alert_id.

        Returns None if not found.
        """
        ...

    async def get_correlated_events(
        self,
        flow_id: int,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Return all EVE events matching flow_id within the optional time window.

        Used by the triage pipeline to assemble the evidence chain for a verdict.
        Includes ALL event types on that flow — flow, http, dns, tls, fileinfo,
        anomaly, AND alert events (alerts are indexed to eve_events alongside
        all other types by the broadcaster→indexer path, so the triage pipeline
        can include them in the correlated context).

        Args:
            flow_id:  Suricata flow_id to look up.
            since:    Optional lower bound (inclusive) on event_timestamp.
            until:    Optional upper bound (inclusive) on event_timestamp.

        Returns:
            List of raw EVE event dicts, ordered by event_timestamp ascending.
        """
        ...

    async def query_alerts(
        self,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
        status: str | None = None,
        sensor_id: int | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """Query alerts with optional filters.

        Args:
            since:      Lower bound on event_timestamp (inclusive).
            until:      Upper bound on event_timestamp (inclusive).
            status:     Filter by status ('queued', 'deferred', 'analyzed', 'failed').
            sensor_id:  Filter by sensor (always 1 in v0.1).
            limit:      Max rows to return.
            offset:     Rows to skip (for pagination).

        Returns:
            List of alert dicts ordered by event_timestamp descending.
        """
        ...

    async def count_analyzed_today(self, sensor_id: int = 1) -> int:
        """Return the number of alerts auto-analyzed since midnight today.

        Used by the dispatcher to enforce VX_TRIAGE_DAILY_CAP.
        """
        ...

    async def update_alert_status(self, alert_id: str, status: str) -> None:
        """Update the status column of an existing alert row.

        Valid status values: 'queued', 'deferred', 'analyzing', 'analyzed', 'failed'.
        """
        ...

    async def update_alert_role_assignment(
        self,
        alert_id: str,
        role: "RoleAssignment",
    ) -> None:
        """Persist role assignment fields on an existing alert row.

        Called by the triage worker after assign_roles() so the UI can display
        initiator/attacker/victim without re-parsing the evidence chain JSON.
        """
        ...

    async def find_recent_verdict_for_group(
        self,
        signature_id: int | None,
        src_ip: str | None,
        dst_ip: str | None,
        *,
        window_hours: int = 1,
    ) -> str | None:
        """Return a verdict_id for a recently-analyzed alert with the same
        (signature_id, src_ip, dst_ip), or None if no match exists.

        Used by the triage worker to skip redundant LLM calls when the same
        alert pattern fires repeatedly (C2 beaconing, scan traffic, etc.).
        The window matches the queue display grouping window (default 1 hour).
        """
        ...

    async def count_alerts_by_status(
        self,
        since: datetime | None = None,
    ) -> dict[str, int]:
        """Return alert counts keyed by status for the given time window.

        Used by the queue view to populate header counters independently of
        the display limit / status filter applied to the visible rows.

        Returns a dict like {"queued": 5, "analyzed": 12, "deferred": 847, ...}.
        Keys only appear when their count is > 0.
        """
        ...

    async def delete_expired_eve_events(self, retention_days: int) -> int:
        """Delete EVE events older than retention_days. Returns row count deleted.

        Called by the nightly cleanup task. Only touches the eve_events table —
        the alerts table is retained indefinitely (ADR-003).
        """
        ...
