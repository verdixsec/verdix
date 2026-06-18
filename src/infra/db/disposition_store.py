# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Concrete SQLite implementation of the DispositionStore interface.

Application code must import DispositionStore from src.interfaces.disposition_store,
not this module directly. Use dependency injection to provide an instance.

The dispositions table is append-only — this implementation never issues
UPDATE or DELETE against it. Multiple rows per alert are expected; callers
use get_latest_disposition() to find the current state.

Depends on src.infra.db.session.init_db() being called at application startup.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy import inspect as sa_inspect

from src.infra.db.models import Disposition
from src.infra.db.session import get_session


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _to_dict(obj: Any) -> dict[str, Any]:
    return {c.key: getattr(obj, c.key) for c in sa_inspect(type(obj)).mapper.column_attrs}


class SQLiteDispositionStore:
    """DispositionStore backed by SQLite via SQLAlchemy async."""

    async def record_disposition(self, disposition: dict[str, Any]) -> str:
        """Persist a new disposition row and return its disposition_id."""
        row = {
            "disposition_id": disposition.get("disposition_id") or str(uuid.uuid4()),
            "alert_id": disposition["alert_id"],
            "verdict_id": disposition.get("verdict_id"),
            "analyst_user_id": disposition["analyst_user_id"],
            "disposition_action": disposition["disposition_action"],
            "override_category": disposition.get("override_category"),
            "override_reason_freetext": disposition.get("override_reason_freetext"),
            "schema_version": disposition.get("schema_version", 1),
            "created_at": disposition.get("created_at") or _now(),
        }
        async with get_session() as session:
            await session.execute(sa.insert(Disposition), row)
        return row["disposition_id"]

    async def get_disposition(self, disposition_id: str) -> dict[str, Any] | None:
        async with get_session() as session:
            result = await session.execute(
                sa.select(Disposition).where(Disposition.disposition_id == disposition_id)
            )
            row = result.scalars().first()
            return _to_dict(row) if row else None

    async def get_latest_disposition(self, alert_id: str) -> dict[str, Any] | None:
        async with get_session() as session:
            result = await session.execute(
                sa.select(Disposition)
                .where(Disposition.alert_id == alert_id)
                .order_by(Disposition.created_at.desc())
                .limit(1)
            )
            row = result.scalars().first()
            return _to_dict(row) if row else None

    async def get_dispositions_for_alert(self, alert_id: str) -> list[dict[str, Any]]:
        async with get_session() as session:
            result = await session.execute(
                sa.select(Disposition)
                .where(Disposition.alert_id == alert_id)
                .order_by(Disposition.created_at.desc())
            )
            return [_to_dict(row) for row in result.scalars().all()]
