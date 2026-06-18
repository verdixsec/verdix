# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""SQLAlchemy ORM models — source of truth for the database schema.

Migration #1 tables:
  alerts                — every Suricata alert ingested (retained indefinitely, ADR-003)
  eve_events            — non-alert EVE events for flow correlation (7-day retention, ADR-003)
  suricata_config_facts — facts extracted from suricata.yaml at each read (ADR-011)

Migration #2 tables:
  verdicts              — AI verdict for each alert (multiple allowed; is_current marks latest)
  dispositions          — analyst accept/override decisions (versioned training corpus)
  users                 — local accounts (single 'admin' row in v0.1; multi-user in v1)
  system_config         — key/value store for EULA acceptance, setup state, etc.

Tables reserved for v1 migrations:
  environment_knowledge_facts, audit_log_entries
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Alert(Base):
    """One row per Suricata EVE alert event ingested.

    Retained indefinitely — forms the training corpus for ML improvements.
    sensor_id is always 1 in v0.1; multi-sensor is the commercial v1 feature.
    """

    __tablename__ = "alerts"

    alert_id: Mapped[str] = mapped_column(sa.String(36), primary_key=True)
    sensor_id: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=1)

    # Suricata identifiers
    eve_alert_uuid: Mapped[str | None] = mapped_column(sa.String(36), nullable=True)
    signature_id: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    signature_msg: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    signature_severity: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    flow_id: Mapped[int | None] = mapped_column(sa.BigInteger, nullable=True)

    # Network 5-tuple
    src_ip: Mapped[str | None] = mapped_column(sa.String(45), nullable=True)
    src_port: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(sa.String(45), nullable=True)
    dst_port: Mapped[int | None] = mapped_column(sa.Integer, nullable=True)
    proto: Mapped[str | None] = mapped_column(sa.String(10), nullable=True)
    app_proto: Mapped[str | None] = mapped_column(sa.String(32), nullable=True)

    # Timestamps
    event_timestamp: Mapped[str | None] = mapped_column(sa.String(40), nullable=True)
    ingest_timestamp: Mapped[str] = mapped_column(sa.String(40), nullable=False)

    # Full raw EVE JSON stored for replay and evidence chain reconstruction
    raw_eve: Mapped[str] = mapped_column(sa.Text, nullable=False)

    # Role assignment (populated by role assigner in Days 7-8)
    home_net_match: Mapped[str | None] = mapped_column(sa.String(4), nullable=True)
    initiator_role: Mapped[str | None] = mapped_column(sa.String(16), nullable=True)
    target_role: Mapped[str | None] = mapped_column(sa.String(16), nullable=True)
    attacker_role: Mapped[str | None] = mapped_column(sa.String(16), nullable=True)
    victim_role: Mapped[str | None] = mapped_column(sa.String(16), nullable=True)
    role_assignment_confidence: Mapped[str | None] = mapped_column(sa.String(16), nullable=True)
    role_assignment_reasoning: Mapped[str | None] = mapped_column(sa.Text, nullable=True)
    role_assignment_signals: Mapped[str | None] = mapped_column(sa.Text, nullable=True)

    # Queue / triage state (ADR-009)
    # Values: 'queued' | 'deferred' | 'analyzing' | 'analyzed' | 'failed'
    status: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="queued")
    auto_analyzed: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=False)

    # Foreign keys populated after verdict / disposition (nullable until then)
    verdict_id: Mapped[str | None] = mapped_column(sa.String(36), nullable=True)
    disposition_id: Mapped[str | None] = mapped_column(sa.String(36), nullable=True)

    __table_args__ = (
        sa.Index("ix_alerts_flow_id", "flow_id"),
        sa.Index("ix_alerts_event_timestamp", "event_timestamp"),
        sa.Index("ix_alerts_status", "status"),
        sa.Index("ix_alerts_sensor_id", "sensor_id"),
        sa.Index("ix_alerts_ingest_timestamp", "ingest_timestamp"),
    )


class EveEvent(Base):
    """One row per non-alert EVE event (flow, http, dns, tls, fileinfo, anomaly).

    Retained for VX_EVE_CONTEXT_RETENTION_DAYS (default 7 days, ADR-003).
    Indexed on flow_id for fast correlation queries during verdict generation.
    """

    __tablename__ = "eve_events"

    event_id: Mapped[str] = mapped_column(sa.String(36), primary_key=True)
    sensor_id: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=1)
    event_type: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    flow_id: Mapped[int | None] = mapped_column(sa.BigInteger, nullable=True)
    event_timestamp: Mapped[str | None] = mapped_column(sa.String(40), nullable=True)
    ingest_timestamp: Mapped[str] = mapped_column(sa.String(40), nullable=False)

    # Full raw EVE JSON
    raw_eve: Mapped[str] = mapped_column(sa.Text, nullable=False)

    __table_args__ = (
        sa.Index("ix_eve_events_flow_id", "flow_id"),
        sa.Index("ix_eve_events_event_timestamp", "event_timestamp"),
        sa.Index("ix_eve_events_event_type", "event_type"),
        sa.Index("ix_eve_events_sensor_id", "sensor_id"),
    )


class SuricataConfigFact(Base):
    """Facts extracted from suricata.yaml at each read (ADR-011).

    One row per fact. is_current=True only for the most recent read.
    fact_type values: 'home_net', 'external_net', 'server_group', 'port_group'
    """

    __tablename__ = "suricata_config_facts"

    fact_id: Mapped[str] = mapped_column(sa.String(36), primary_key=True)
    fact_type: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    fact_key: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    fact_value: Mapped[str] = mapped_column(sa.Text, nullable=False)
    read_at: Mapped[str] = mapped_column(sa.String(40), nullable=False)
    is_current: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)

    __table_args__ = (
        sa.Index("ix_suricata_config_facts_is_current", "is_current"),
        sa.Index("ix_suricata_config_facts_fact_type", "fact_type"),
    )


# ---------------------------------------------------------------------------
# Migration #2 — verdicts, dispositions, users, system_config
# ---------------------------------------------------------------------------


class Verdict(Base):
    """One AI verdict per triage run. Multiple rows per alert allowed;
    is_current=True marks the latest. Stores every input the LLM received so
    the analyst can inspect reasoning end-to-end ('show reasoning' in UI).
    """

    __tablename__ = "verdicts"

    verdict_id: Mapped[str] = mapped_column(sa.String(36), primary_key=True)
    alert_id: Mapped[str] = mapped_column(sa.String(36), nullable=False)

    verdict_category: Mapped[str] = mapped_column(sa.String(32), nullable=False)
    confidence_score: Mapped[float] = mapped_column(sa.Float, nullable=False)
    reasoning: Mapped[str] = mapped_column(sa.Text, nullable=False)
    contributing_facts: Mapped[str] = mapped_column(sa.Text, nullable=False)  # JSON list

    # Full evidence chain — EVE records, enrichment results, config facts (JSON)
    evidence_chain: Mapped[str] = mapped_column(sa.Text, nullable=False)

    # Provenance — required for regression testing and disposition training corpus
    model_version: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    prompt_version: Mapped[str] = mapped_column(sa.String(64), nullable=False)

    # Raw LLM I/O stored for 'show reasoning' and future fine-tuning
    llm_inputs: Mapped[str] = mapped_column(sa.Text, nullable=False)   # JSON
    llm_raw_output: Mapped[str] = mapped_column(sa.Text, nullable=False)  # JSON

    latency_ms: Mapped[int] = mapped_column(sa.Integer, nullable=False)
    is_current: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)
    created_at: Mapped[str] = mapped_column(sa.String(40), nullable=False)

    __table_args__ = (
        sa.Index("ix_verdicts_alert_id", "alert_id"),
        sa.Index("ix_verdicts_is_current", "is_current"),
        sa.Index("ix_verdicts_created_at", "created_at"),
    )


class Disposition(Base):
    """Analyst accept/override decision. Append-only training corpus — rows are
    never updated or deleted. Multiple rows per alert are allowed; queries use
    ORDER BY created_at DESC to find the latest.

    schema_version is captured at write time so future migrations can identify
    which fields were available when each row was written.
    """

    __tablename__ = "dispositions"

    disposition_id: Mapped[str] = mapped_column(sa.String(36), primary_key=True)
    alert_id: Mapped[str] = mapped_column(sa.String(36), nullable=False)
    verdict_id: Mapped[str | None] = mapped_column(sa.String(36), nullable=True)
    analyst_user_id: Mapped[str] = mapped_column(sa.String(36), nullable=False)

    # 'accept' — analyst agrees with AI verdict
    # 'override' — analyst disagrees; override_category holds their verdict
    disposition_action: Mapped[str] = mapped_column(sa.String(16), nullable=False)
    override_category: Mapped[str | None] = mapped_column(sa.String(32), nullable=True)
    override_reason_freetext: Mapped[str | None] = mapped_column(sa.Text, nullable=True)

    schema_version: Mapped[int] = mapped_column(sa.Integer, nullable=False, default=1)
    created_at: Mapped[str] = mapped_column(sa.String(40), nullable=False)

    __table_args__ = (
        sa.Index("ix_dispositions_alert_id", "alert_id"),
        sa.Index("ix_dispositions_analyst_user_id", "analyst_user_id"),
        sa.Index("ix_dispositions_created_at", "created_at"),
    )


class User(Base):
    """Local user account. Single 'admin' row in v0.1 (static env-var password).
    password_hash is null in v0.1; populated in v1 when local-account auth ships.
    """

    __tablename__ = "users"

    user_id: Mapped[str] = mapped_column(sa.String(36), primary_key=True)
    username: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    password_hash: Mapped[str | None] = mapped_column(sa.String(256), nullable=True)
    role: Mapped[str] = mapped_column(sa.String(16), nullable=False, default="admin")
    created_at: Mapped[str] = mapped_column(sa.String(40), nullable=False)
    last_login_at: Mapped[str | None] = mapped_column(sa.String(40), nullable=True)
    is_active: Mapped[bool] = mapped_column(sa.Boolean, nullable=False, default=True)

    __table_args__ = (
        sa.UniqueConstraint("username", name="uq_users_username"),
        sa.Index("ix_users_username", "username"),
    )


class SystemConfig(Base):
    """Key/value store for application-level configuration that must survive
    container restarts. Keys used in v0.1:
      eula_accepted      — 'true' once the analyst has accepted the Community License
      eula_accepted_at   — ISO-8601 timestamp of acceptance
      setup_complete     — 'true' once initial setup is done
    """

    __tablename__ = "system_config"

    config_key: Mapped[str] = mapped_column(sa.String(128), primary_key=True)
    config_value: Mapped[str] = mapped_column(sa.Text, nullable=False)
    updated_at: Mapped[str] = mapped_column(sa.String(40), nullable=False)
