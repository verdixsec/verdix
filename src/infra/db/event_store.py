# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Concrete SQLite implementation of the EventStore interface.

Application code must import EventStore from src.interfaces.event_store,
not this module directly. Use dependency injection to provide an instance.

Depends on src.infra.db.session.init_db() being called at application startup
before any EventStore method is invoked.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import sqlalchemy as sa
from sqlalchemy import inspect as sa_inspect

from src.domain.role_assignment.models import RoleAssignment
from src.infra.db.models import Alert, EveEvent
from src.infra.db.session import get_session


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _to_dict(obj: Any) -> dict[str, Any]:
    return {c.key: getattr(obj, c.key) for c in sa_inspect(type(obj)).mapper.column_attrs}


class SQLiteEventStore:
    """EventStore backed by SQLite via SQLAlchemy async (aiosqlite driver)."""

    async def insert_eve_event(self, event: dict[str, Any]) -> None:
        """Persist a single raw EVE event (non-alert)."""
        async with get_session() as session:
            await session.execute(
                sa.insert(EveEvent),
                {
                    "event_id": str(uuid.uuid4()),
                    "sensor_id": 1,
                    "event_type": event.get("event_type", "unknown"),
                    "flow_id": event.get("flow_id"),
                    "event_timestamp": event.get("timestamp"),
                    "ingest_timestamp": _now(),
                    "raw_eve": json.dumps(event),
                },
            )

    async def insert_eve_events_batch(self, events: list[dict[str, Any]]) -> None:
        """Persist a batch of raw EVE events in a single transaction."""
        if not events:
            return
        now = _now()
        rows = [
            {
                "event_id": str(uuid.uuid4()),
                "sensor_id": 1,
                "event_type": e.get("event_type", "unknown"),
                "flow_id": e.get("flow_id"),
                "event_timestamp": e.get("timestamp"),
                "ingest_timestamp": now,
                "raw_eve": json.dumps(e),
            }
            for e in events
        ]
        async with get_session() as session:
            await session.execute(sa.insert(EveEvent), rows)

    async def insert_alert(self, alert: dict[str, Any], *, status: str = "queued") -> str:
        """Persist an alert and return its locally-generated alert_id."""
        alert_id = str(uuid.uuid4())
        alert_fields = alert.get("alert", {})
        async with get_session() as session:
            await session.execute(
                sa.insert(Alert),
                {
                    "alert_id": alert_id,
                    "sensor_id": 1,
                    "signature_id": alert_fields.get("signature_id"),
                    "signature_msg": alert_fields.get("signature"),
                    "signature_severity": alert_fields.get("severity"),
                    "flow_id": alert.get("flow_id"),
                    "src_ip": alert.get("src_ip"),
                    "src_port": alert.get("src_port"),
                    "dst_ip": alert.get("dest_ip"),   # EVE uses dest_ip, not dst_ip
                    "dst_port": alert.get("dest_port"),
                    "proto": alert.get("proto"),
                    "app_proto": alert.get("app_proto"),
                    "event_timestamp": alert.get("timestamp"),
                    "ingest_timestamp": _now(),
                    "raw_eve": json.dumps(alert),
                    "status": status,
                    "auto_analyzed": False,
                },
            )
        return alert_id

    async def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        """Retrieve a single alert by alert_id. Returns None if not found."""
        async with get_session() as session:
            result = await session.execute(
                sa.select(Alert).where(Alert.alert_id == alert_id)
            )
            row = result.scalars().first()
            return _to_dict(row) if row else None

    async def get_correlated_events(
        self,
        flow_id: int,
        *,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """Return all EVE events matching flow_id within the optional time window."""
        async with get_session() as session:
            query = (
                sa.select(EveEvent)
                .where(EveEvent.flow_id == flow_id)
                .order_by(EveEvent.event_timestamp.asc())
            )
            if since is not None:
                query = query.where(EveEvent.event_timestamp >= since.isoformat())
            if until is not None:
                query = query.where(EveEvent.event_timestamp <= until.isoformat())
            result = await session.execute(query)
            return [_to_dict(row) for row in result.scalars().all()]

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
        """Query alerts with optional filters, ordered by ingest_timestamp descending."""
        async with get_session() as session:
            query = sa.select(Alert).order_by(Alert.ingest_timestamp.desc())
            if since is not None:
                query = query.where(Alert.ingest_timestamp >= since.isoformat())
            if until is not None:
                query = query.where(Alert.ingest_timestamp <= until.isoformat())
            if status is not None:
                query = query.where(Alert.status == status)
            if sensor_id is not None:
                query = query.where(Alert.sensor_id == sensor_id)
            query = query.limit(limit).offset(offset)
            result = await session.execute(query)
            return [_to_dict(row) for row in result.scalars().all()]

    async def count_analyzed_today(self, sensor_id: int = 1) -> int:
        """Count non-deferred alerts ingested since today's reset hour.

        The reset hour is read from VX_DAILY_RESET_HOUR (default 0 = midnight UTC).
        """
        reset_hour = int(os.environ.get("VX_DAILY_RESET_HOUR", "0"))
        reset_time = datetime.now(UTC).replace(
            hour=reset_hour, minute=0, second=0, microsecond=0
        )
        async with get_session() as session:
            result = await session.execute(
                sa.select(sa.func.count())
                .select_from(Alert)
                .where(
                    Alert.sensor_id == sensor_id,
                    Alert.status != "deferred",
                    Alert.ingest_timestamp >= reset_time.isoformat(),
                )
            )
            return result.scalar() or 0

    async def update_alert_status(self, alert_id: str, status: str) -> None:
        """Update the status of an existing alert row."""
        async with get_session() as session:
            await session.execute(
                sa.update(Alert)
                .where(Alert.alert_id == alert_id)
                .values(status=status)
            )

    async def update_alert_role_assignment(self, alert_id: str, role: RoleAssignment) -> None:
        """Persist role assignment fields on an existing alert row."""
        async with get_session() as session:
            await session.execute(
                sa.update(Alert)
                .where(Alert.alert_id == alert_id)
                .values(
                    initiator_role=role.initiator_ip,
                    target_role=role.responder_ip,
                    attacker_role=role.attacker_ip,
                    victim_role=role.victim_ip,
                    role_assignment_confidence=role.confidence,
                    role_assignment_reasoning=role.reasoning,
                    role_assignment_signals=json.dumps(role.signals_used),
                )
            )

    async def find_recent_verdict_for_group(
        self,
        signature_id: int | None,
        src_ip: str | None,
        dst_ip: str | None,
        *,
        window_hours: int = 1,
    ) -> str | None:
        """Return the verdict_id of the most recently-analyzed alert with the
        same (signature_id, src_ip, dst_ip) within window_hours, or None."""
        if signature_id is None or src_ip is None or dst_ip is None:
            return None
        since = (datetime.now(UTC) - timedelta(hours=window_hours)).isoformat()
        async with get_session() as session:
            result = await session.execute(
                sa.select(Alert.verdict_id)
                .where(
                    Alert.signature_id == signature_id,
                    Alert.src_ip == src_ip,
                    Alert.dst_ip == dst_ip,
                    Alert.status == "analyzed",
                    Alert.verdict_id.isnot(None),
                    Alert.ingest_timestamp >= since,
                )
                .order_by(Alert.ingest_timestamp.desc())
                .limit(1)
            )
            return result.scalars().first()

    async def count_alerts_by_status(
        self,
        since: datetime | None = None,
    ) -> dict[str, int]:
        """Return alert counts keyed by status for the given time window."""
        async with get_session() as session:
            query = sa.select(Alert.status, sa.func.count().label("cnt")).group_by(
                Alert.status
            )
            if since is not None:
                query = query.where(Alert.ingest_timestamp >= since.isoformat())
            result = await session.execute(query)
            return {row[0]: row[1] for row in result.all()}

    async def delete_expired_eve_events(self, retention_days: int) -> int:
        """Delete EVE events older than retention_days. Returns deleted row count."""
        cutoff = (datetime.now(UTC) - timedelta(days=retention_days)).isoformat()
        async with get_session() as session:
            result = await session.execute(
                sa.delete(EveEvent).where(EveEvent.event_timestamp < cutoff)
            )
            return result.rowcount
