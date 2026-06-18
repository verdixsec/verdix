# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Concrete SQLite implementation of the OperationalStore interface.

Application code must import OperationalStore from src.interfaces.operational_store,
not this module directly. Use dependency injection to provide an instance.

Depends on src.infra.db.session.init_db() being called at application startup.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from sqlalchemy import inspect as sa_inspect

from src.infra.db.models import Alert, Disposition, SystemConfig, User, Verdict
from src.infra.db.session import get_session


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _to_dict(obj: Any) -> dict[str, Any]:
    return {c.key: getattr(obj, c.key) for c in sa_inspect(type(obj)).mapper.column_attrs}


class SQLiteOperationalStore:
    """OperationalStore backed by SQLite via SQLAlchemy async."""

    # ------------------------------------------------------------------
    # System config
    # ------------------------------------------------------------------

    async def get_config(self, key: str) -> str | None:
        async with get_session() as session:
            result = await session.execute(
                sa.select(SystemConfig).where(SystemConfig.config_key == key)
            )
            row = result.scalars().first()
            return row.config_value if row else None

    async def set_config(self, key: str, value: str) -> None:
        async with get_session() as session:
            existing = await session.execute(
                sa.select(SystemConfig).where(SystemConfig.config_key == key)
            )
            row = existing.scalars().first()
            if row is None:
                await session.execute(
                    sa.insert(SystemConfig),
                    {"config_key": key, "config_value": value, "updated_at": _now()},
                )
            else:
                await session.execute(
                    sa.update(SystemConfig)
                    .where(SystemConfig.config_key == key)
                    .values(config_value=value, updated_at=_now())
                )

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    async def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        async with get_session() as session:
            result = await session.execute(
                sa.select(User).where(User.username == username)
            )
            row = result.scalars().first()
            return _to_dict(row) if row else None

    async def ensure_admin_user(self, user_id: str) -> None:
        """Create the 'admin' user row if it does not already exist."""
        async with get_session() as session:
            existing = await session.execute(
                sa.select(User).where(User.username == "admin")
            )
            if existing.scalars().first() is None:
                await session.execute(
                    sa.insert(User),
                    {
                        "user_id": user_id,
                        "username": "admin",
                        "password_hash": None,
                        "role": "admin",
                        "created_at": _now(),
                        "last_login_at": None,
                        "is_active": True,
                    },
                )

    async def update_last_login(self, user_id: str) -> None:
        async with get_session() as session:
            await session.execute(
                sa.update(User)
                .where(User.user_id == user_id)
                .values(last_login_at=_now())
            )

    # ------------------------------------------------------------------
    # Verdicts
    # ------------------------------------------------------------------

    async def record_verdict(self, verdict: dict[str, Any]) -> None:
        if "verdict_id" not in verdict:
            verdict = {**verdict, "verdict_id": str(uuid.uuid4())}
        if "created_at" not in verdict:
            verdict = {**verdict, "created_at": _now()}
        async with get_session() as session:
            await session.execute(sa.insert(Verdict), verdict)

    async def mark_previous_verdicts_superseded(self, alert_id: str) -> None:
        async with get_session() as session:
            await session.execute(
                sa.update(Verdict)
                .where(Verdict.alert_id == alert_id, Verdict.is_current.is_(True))
                .values(is_current=False)
            )

    async def get_verdict(self, verdict_id: str) -> dict[str, Any] | None:
        async with get_session() as session:
            result = await session.execute(
                sa.select(Verdict).where(Verdict.verdict_id == verdict_id)
            )
            row = result.scalars().first()
            return _to_dict(row) if row else None

    async def get_current_verdict_for_alert(self, alert_id: str) -> dict[str, Any] | None:
        async with get_session() as session:
            result = await session.execute(
                sa.select(Verdict)
                .where(Verdict.alert_id == alert_id, Verdict.is_current.is_(True))
            )
            row = result.scalars().first()
            return _to_dict(row) if row else None

    # ------------------------------------------------------------------
    # Alert FK updates
    # ------------------------------------------------------------------

    async def link_verdict_to_alert(self, alert_id: str, verdict_id: str) -> None:
        async with get_session() as session:
            await session.execute(
                sa.update(Alert)
                .where(Alert.alert_id == alert_id)
                .values(verdict_id=verdict_id, status="analyzed", auto_analyzed=True)
            )

    async def link_disposition_to_alert(self, alert_id: str, disposition_id: str) -> None:
        async with get_session() as session:
            await session.execute(
                sa.update(Alert)
                .where(Alert.alert_id == alert_id)
                .values(disposition_id=disposition_id)
            )
