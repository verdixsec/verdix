# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Initial schema: alerts, eve_events, suricata_config_facts.

Revision ID: 0001
Revises: None
Create Date: 2026-05-09 00:00:00

This is migration #1. The framework is in place for v1's first real migration.
All tables include sensor_id from row one (multi-sensor is the v1 commercial
conversion event; always 1 in v0.1).

Forward-only — downgrade() is intentionally a no-op.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # alerts — one row per Suricata EVE alert ingested.
    # Retained indefinitely (ADR-003). Forms the training corpus.
    # ------------------------------------------------------------------
    op.create_table(
        "alerts",
        sa.Column("alert_id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("sensor_id", sa.Integer, nullable=False, server_default="1"),

        # Suricata identifiers
        sa.Column("eve_alert_uuid", sa.String(36), nullable=True),
        sa.Column("signature_id", sa.Integer, nullable=True),
        sa.Column("signature_msg", sa.Text, nullable=True),
        sa.Column("signature_severity", sa.Integer, nullable=True),
        sa.Column("flow_id", sa.BigInteger, nullable=True),

        # Network 5-tuple
        sa.Column("src_ip", sa.String(45), nullable=True),
        sa.Column("src_port", sa.Integer, nullable=True),
        sa.Column("dst_ip", sa.String(45), nullable=True),
        sa.Column("dst_port", sa.Integer, nullable=True),
        sa.Column("proto", sa.String(10), nullable=True),
        sa.Column("app_proto", sa.String(32), nullable=True),

        # Timestamps stored as ISO-8601 strings to preserve Suricata's precision
        sa.Column("event_timestamp", sa.String(40), nullable=True),
        sa.Column("ingest_timestamp", sa.String(40), nullable=False),

        # Full raw EVE JSON for replay and evidence chain reconstruction
        sa.Column("raw_eve", sa.Text, nullable=False),

        # Role assignment columns — populated by role assigner (Days 7-8)
        # home_net_match: 'src' | 'dst' | 'both' | None
        sa.Column("home_net_match", sa.String(4), nullable=True),
        sa.Column("initiator_role", sa.String(16), nullable=True),
        sa.Column("target_role", sa.String(16), nullable=True),
        sa.Column("attacker_role", sa.String(16), nullable=True),
        sa.Column("victim_role", sa.String(16), nullable=True),
        sa.Column("role_assignment_confidence", sa.String(16), nullable=True),
        sa.Column("role_assignment_reasoning", sa.Text, nullable=True),
        sa.Column("role_assignment_signals", sa.Text, nullable=True),  # JSON array

        # Queue / triage state (ADR-009)
        # status: 'queued' | 'deferred' | 'analyzing' | 'analyzed' | 'failed'
        sa.Column("status", sa.String(16), nullable=False, server_default="queued"),
        sa.Column("auto_analyzed", sa.Boolean, nullable=False, server_default="0"),

        # FK stubs — populated after verdict / disposition (nullable until then)
        sa.Column("verdict_id", sa.String(36), nullable=True),
        sa.Column("disposition_id", sa.String(36), nullable=True),
    )

    op.create_index("ix_alerts_flow_id", "alerts", ["flow_id"])
    op.create_index("ix_alerts_event_timestamp", "alerts", ["event_timestamp"])
    op.create_index("ix_alerts_status", "alerts", ["status"])
    op.create_index("ix_alerts_sensor_id", "alerts", ["sensor_id"])
    op.create_index("ix_alerts_ingest_timestamp", "alerts", ["ingest_timestamp"])

    # ------------------------------------------------------------------
    # eve_events — non-alert EVE events for flow correlation.
    # 7-day retention via nightly cleanup (VX_EVE_CONTEXT_RETENTION_DAYS, ADR-003).
    # ------------------------------------------------------------------
    op.create_table(
        "eve_events",
        sa.Column("event_id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("sensor_id", sa.Integer, nullable=False, server_default="1"),
        sa.Column("event_type", sa.String(32), nullable=False),
        sa.Column("flow_id", sa.BigInteger, nullable=True),
        sa.Column("event_timestamp", sa.String(40), nullable=True),
        sa.Column("ingest_timestamp", sa.String(40), nullable=False),
        sa.Column("raw_eve", sa.Text, nullable=False),
    )

    op.create_index("ix_eve_events_flow_id", "eve_events", ["flow_id"])
    op.create_index("ix_eve_events_event_timestamp", "eve_events", ["event_timestamp"])
    op.create_index("ix_eve_events_event_type", "eve_events", ["event_type"])
    op.create_index("ix_eve_events_sensor_id", "eve_events", ["sensor_id"])

    # ------------------------------------------------------------------
    # suricata_config_facts — extracted from suricata.yaml at each read.
    # is_current=1 only for facts from the most recent read (ADR-011).
    # fact_type: 'home_net' | 'external_net' | 'server_group' | 'port_group'
    # ------------------------------------------------------------------
    op.create_table(
        "suricata_config_facts",
        sa.Column("fact_id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("fact_type", sa.String(32), nullable=False),
        sa.Column("fact_key", sa.String(128), nullable=False),
        sa.Column("fact_value", sa.Text, nullable=False),
        sa.Column("read_at", sa.String(40), nullable=False),
        sa.Column("is_current", sa.Boolean, nullable=False, server_default="1"),
    )

    op.create_index("ix_suricata_config_facts_is_current", "suricata_config_facts", ["is_current"])
    op.create_index("ix_suricata_config_facts_fact_type", "suricata_config_facts", ["fact_type"])


def downgrade() -> None:
    # Forward-only migrations — downgrade is intentionally not supported in v0.1.
    pass
