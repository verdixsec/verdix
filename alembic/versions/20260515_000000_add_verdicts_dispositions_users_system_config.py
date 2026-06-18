# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Add verdicts, dispositions, users, system_config tables.

Revision ID: 0002
Revises: 0001
Create Date: 2026-05-15 00:00:00

Forward-only — downgrade() is intentionally a no-op.
"""
from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # verdicts — one AI verdict per triage run; multiple rows per alert.
    # is_current=1 marks the latest verdict for a given alert.
    # Stores full LLM I/O for 'show reasoning' and future fine-tuning.
    # ------------------------------------------------------------------
    op.create_table(
        "verdicts",
        sa.Column("verdict_id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("alert_id", sa.String(36), nullable=False),
        sa.Column("verdict_category", sa.String(32), nullable=False),
        sa.Column("confidence_score", sa.Float, nullable=False),
        sa.Column("reasoning", sa.Text, nullable=False),
        sa.Column("contributing_facts", sa.Text, nullable=False),   # JSON list
        sa.Column("evidence_chain", sa.Text, nullable=False),       # JSON object
        sa.Column("model_version", sa.String(128), nullable=False),
        sa.Column("prompt_version", sa.String(64), nullable=False),
        sa.Column("llm_inputs", sa.Text, nullable=False),           # JSON
        sa.Column("llm_raw_output", sa.Text, nullable=False),       # JSON
        sa.Column("latency_ms", sa.Integer, nullable=False),
        sa.Column("is_current", sa.Boolean, nullable=False, server_default="1"),
        sa.Column("created_at", sa.String(40), nullable=False),
    )
    op.create_index("ix_verdicts_alert_id", "verdicts", ["alert_id"])
    op.create_index("ix_verdicts_is_current", "verdicts", ["is_current"])
    op.create_index("ix_verdicts_created_at", "verdicts", ["created_at"])

    # ------------------------------------------------------------------
    # dispositions — analyst accept/override decisions.
    # Append-only training corpus; rows are never updated or deleted.
    # schema_version captured at write time for future migration safety.
    # ------------------------------------------------------------------
    op.create_table(
        "dispositions",
        sa.Column("disposition_id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("alert_id", sa.String(36), nullable=False),
        sa.Column("verdict_id", sa.String(36), nullable=True),
        sa.Column("analyst_user_id", sa.String(36), nullable=False),
        sa.Column("disposition_action", sa.String(16), nullable=False),
        sa.Column("override_category", sa.String(32), nullable=True),
        sa.Column("override_reason_freetext", sa.Text, nullable=True),
        sa.Column("schema_version", sa.Integer, nullable=False, server_default="1"),
        sa.Column("created_at", sa.String(40), nullable=False),
    )
    op.create_index("ix_dispositions_alert_id", "dispositions", ["alert_id"])
    op.create_index("ix_dispositions_analyst_user_id", "dispositions", ["analyst_user_id"])
    op.create_index("ix_dispositions_created_at", "dispositions", ["created_at"])

    # ------------------------------------------------------------------
    # users — local accounts. Single 'admin' row in v0.1.
    # password_hash is null in v0.1 (auth via VX_ADMIN_PASSWORD env var).
    # ------------------------------------------------------------------
    op.create_table(
        "users",
        sa.Column("user_id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("username", sa.String(128), nullable=False),
        sa.Column("password_hash", sa.String(256), nullable=True),
        sa.Column("role", sa.String(16), nullable=False, server_default="admin"),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("last_login_at", sa.String(40), nullable=True),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="1"),
    )
    op.create_index("ix_users_username", "users", ["username"], unique=True)

    # ------------------------------------------------------------------
    # system_config — key/value store for durable application state.
    # Keys: eula_accepted, eula_accepted_at, setup_complete.
    # ------------------------------------------------------------------
    op.create_table(
        "system_config",
        sa.Column("config_key", sa.String(128), primary_key=True, nullable=False),
        sa.Column("config_value", sa.Text, nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
    )


def downgrade() -> None:
    # Forward-only migrations — downgrade is intentionally not supported in v0.1.
    pass
