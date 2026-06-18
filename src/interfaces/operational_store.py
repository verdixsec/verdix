# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""OperationalStore interface — OLTP storage for verdicts, dispositions, users, config.

Concrete implementations:
  v0.1  src/infra/db/operational_store.py  — SQLite via SQLAlchemy async
  v1.x  Postgres (multi-node swap target)

Application code must import this Protocol, never the concrete class.
Concrete instances arrive via dependency injection.

Relationship to EventStore:
  EventStore owns alert/EVE ingestion and status transitions.
  OperationalStore owns verdicts, dispositions, users, and system config — plus
  the FK columns on alerts (verdict_id, disposition_id) that are populated after
  those records are created.
"""
from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class OperationalStore(Protocol):
    """OLTP storage for the triage pipeline and web UI."""

    # ------------------------------------------------------------------
    # System config
    # ------------------------------------------------------------------

    async def get_config(self, key: str) -> str | None:
        """Return the stored value for config_key, or None if not set."""
        ...

    async def set_config(self, key: str, value: str) -> None:
        """Upsert a config key/value pair."""
        ...

    # ------------------------------------------------------------------
    # Users
    # ------------------------------------------------------------------

    async def get_user_by_username(self, username: str) -> dict[str, Any] | None:
        """Return the user row for username, or None if not found."""
        ...

    async def ensure_admin_user(self, user_id: str) -> None:
        """Create the 'admin' user row if it does not already exist.

        Idempotent — safe to call at every application startup.
        password_hash is left null in v0.1 (auth via VX_ADMIN_PASSWORD env var).
        """
        ...

    async def update_last_login(self, user_id: str) -> None:
        """Set last_login_at to the current UTC timestamp for user_id."""
        ...

    # ------------------------------------------------------------------
    # Verdicts
    # ------------------------------------------------------------------

    async def record_verdict(self, verdict: dict[str, Any]) -> None:
        """Persist a new verdict row.

        Caller is responsible for setting is_current=False on any previous
        verdict for the same alert before calling this — use
        mark_previous_verdicts_superseded() for that.

        Required keys in verdict dict:
          verdict_id, alert_id, verdict_category, confidence_score, reasoning,
          contributing_facts (JSON str), evidence_chain (JSON str),
          model_version, prompt_version, llm_inputs (JSON str),
          llm_raw_output (JSON str), latency_ms, is_current, created_at.
        """
        ...

    async def mark_previous_verdicts_superseded(self, alert_id: str) -> None:
        """Set is_current=False on all existing verdict rows for alert_id.

        Call immediately before record_verdict() when re-triaging an alert.
        """
        ...

    async def get_verdict(self, verdict_id: str) -> dict[str, Any] | None:
        """Return a single verdict by verdict_id, or None."""
        ...

    async def get_current_verdict_for_alert(self, alert_id: str) -> dict[str, Any] | None:
        """Return the is_current verdict for alert_id, or None if not yet analyzed."""
        ...

    # ------------------------------------------------------------------
    # Alert FK updates (called by triage worker after persisting verdict/disposition)
    # ------------------------------------------------------------------

    async def link_verdict_to_alert(self, alert_id: str, verdict_id: str) -> None:
        """Set alerts.verdict_id and alerts.status='analyzed', auto_analyzed=True."""
        ...

    async def link_disposition_to_alert(self, alert_id: str, disposition_id: str) -> None:
        """Set alerts.disposition_id for the given alert_id."""
        ...
