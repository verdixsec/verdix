# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""DispositionStore interface — thin layer for analyst disposition workflow.

Concrete implementations:
  v0.1  src/infra/db/disposition_store.py  — SQLite via SQLAlchemy async

Application code must import this Protocol, never the concrete class.
Concrete instances arrive via dependency injection.

The disposition table is an append-only training corpus — rows are never
updated or deleted. Multiple dispositions per alert are allowed; callers
use get_latest_disposition() to find the most recent one.
"""
from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class DispositionStore(Protocol):
    """Capture and query analyst disposition decisions."""

    async def record_disposition(self, disposition: dict[str, Any]) -> str:
        """Persist a new disposition row and return its disposition_id.

        Required keys in disposition dict:
          alert_id, analyst_user_id, disposition_action ('accept' | 'override').
        Optional keys:
          disposition_id (generated if absent), verdict_id, override_category,
          override_reason_freetext, schema_version (defaults to 1), created_at
          (defaults to current UTC).
        """
        ...

    async def get_disposition(self, disposition_id: str) -> dict[str, Any] | None:
        """Return a single disposition by disposition_id, or None."""
        ...

    async def get_latest_disposition(self, alert_id: str) -> dict[str, Any] | None:
        """Return the most recent disposition for alert_id, or None."""
        ...

    async def get_dispositions_for_alert(self, alert_id: str) -> list[dict[str, Any]]:
        """Return all dispositions for alert_id, ordered by created_at descending."""
        ...
