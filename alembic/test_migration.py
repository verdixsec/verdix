# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Alembic migration smoke test.

Verifies that `alembic upgrade head` against a fresh SQLite database produces
all expected v0.1 tables and their key indexes. This guards against the schema
drifting from the migration (previously only `create_all` was exercised in CI).

The test is synchronous — alembic's command API runs its own event loop
internally, which cannot nest inside pytest-asyncio's loop.
"""
from __future__ import annotations

from alembic.config import Config
from sqlalchemy import create_engine
from sqlalchemy import inspect as sa_inspect

from alembic import command


def test_alembic_upgrade_head_creates_all_tables(tmp_path, monkeypatch) -> None:
    """Running alembic upgrade head must produce all v0.1 tables and indexes."""

    db_file = tmp_path / "migration_test.db"
    async_url = f"sqlite+aiosqlite:///{db_file}"

    # Point alembic at the temp DB (env.py reads SC_DB_URL).
    monkeypatch.setenv("VX_DB_URL", async_url)

    cfg = Config("alembic.ini")
    cfg.set_main_option("sqlalchemy.url", async_url)
    command.upgrade(cfg, "head")

    # Inspect the resulting schema with a sync engine.
    sync_url = f"sqlite:///{db_file}"
    engine = create_engine(sync_url)
    inspector = sa_inspect(engine)
    try:
        tables = set(inspector.get_table_names())

        assert "alerts" in tables, "alerts table missing"
        assert "eve_events" in tables, "eve_events table missing"
        assert "suricata_config_facts" in tables, "suricata_config_facts table missing"
        assert "alembic_version" in tables, "alembic_version table missing"

        alert_indexes = {i["name"] for i in inspector.get_indexes("alerts")}
        assert "ix_alerts_flow_id" in alert_indexes
        assert "ix_alerts_status" in alert_indexes
        assert "ix_alerts_event_timestamp" in alert_indexes
        assert "ix_alerts_sensor_id" in alert_indexes

        eve_indexes = {i["name"] for i in inspector.get_indexes("eve_events")}
        assert "ix_eve_events_flow_id" in eve_indexes
        assert "ix_eve_events_event_timestamp" in eve_indexes
    finally:
        engine.dispose()
