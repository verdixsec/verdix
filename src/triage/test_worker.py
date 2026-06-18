# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Integration tests for TriageWorker and EveCleanupTask.

Tests use a real in-memory SQLite database and mock only the LLM and
enrichment clients (external I/O boundaries).
asyncio_mode = "auto" — no @pytest.mark.asyncio needed.
"""
from __future__ import annotations

import ipaddress
import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from src.enrichment.models import (
    EnrichmentResult,
    EnrichmentStatus,
    IndicatorType,
)
from src.infra.db.event_store import SQLiteEventStore
from src.infra.db.operational_store import SQLiteOperationalStore
from src.infra.db.session import close_db, init_db
from src.infra.suricata_config.models import SuricataConfig
from src.llm.models import LLMResponse
from src.triage.cleanup import EveCleanupTask
from src.triage.worker import TriageWorker, _extract_indicators

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
async def fresh_db() -> None:
    await init_db("sqlite+aiosqlite:///:memory:")
    yield
    await close_db()


@pytest.fixture
def event_store() -> SQLiteEventStore:
    return SQLiteEventStore()


@pytest.fixture
def op_store() -> SQLiteOperationalStore:
    return SQLiteOperationalStore()


@pytest.fixture
def suricata_config() -> SuricataConfig:
    return SuricataConfig(
        home_net=[ipaddress.IPv4Network("10.0.0.0/8")],
        external_net=[],
        server_groups={},
        port_groups={},
        rule_file_paths=[],
        rule_file_summaries={},
        config_file_paths_read=[],
        read_at=datetime.now(UTC),
        raw_yaml_hash="test",
    )


@pytest.fixture
def mock_llm() -> MagicMock:
    llm = MagicMock()
    llm.model_version = "gemma4:e4b-it-q8_0"
    llm.complete = AsyncMock(return_value=LLMResponse(
        verdict_category="likely_fp",
        confidence_score=0.85,
        reasoning="Test reasoning — benign traffic pattern.",
        contributing_facts=["No TI hits", "Internal host"],
        raw_output={
            "verdict_category": "likely_fp",
            "confidence_score": 0.85,
            "reasoning": "Test reasoning — benign traffic pattern.",
            "contributing_facts": ["No TI hits", "Internal host"],
        },
        latency_ms=1200,
        model_version="gemma4:e4b-it-q8_0",
        prompt_version="verdict_v1",
        llm_inputs={"prompt": "..."},
        first_attempt_valid=True,
        attempts=1,
    ))
    return llm


def _make_alert_eve(
    flow_id: int = 12345,
    src_ip: str = "10.0.0.5",
    dest_ip: str = "185.220.101.45",
    sig_msg: str = "ET MALWARE Test",
    category: str = "A Network Trojan was Detected",
) -> dict:
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "flow_id": flow_id,
        "event_type": "alert",
        "src_ip": src_ip,
        "src_port": 54321,
        "dest_ip": dest_ip,
        "dest_port": 443,
        "proto": "TCP",
        "app_proto": "tls",
        "alert": {
            "action": "allowed",
            "signature_id": 2000001,
            "signature": sig_msg,
            "severity": 1,
            "category": category,
        },
    }


def _make_dns_event(flow_id: int, domain: str) -> dict:
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "flow_id": flow_id,
        "event_type": "dns",
        "dns": {"type": "query", "rrname": domain},
    }


# ---------------------------------------------------------------------------
# _extract_indicators unit tests
# ---------------------------------------------------------------------------


def test_extract_indicators_ips() -> None:
    raw_eve = {"src_ip": "10.0.0.5", "dest_ip": "185.220.101.45"}
    inds = _extract_indicators(raw_eve, [])
    types = [i.type for i in inds]
    assert IndicatorType.IP in types
    assert len([i for i in inds if i.type is IndicatorType.IP]) == 2


def test_extract_indicators_dns_domains() -> None:
    raw_eve = {"src_ip": "10.0.0.5", "dest_ip": "1.2.3.4"}
    correlated = [
        _make_dns_event(1, "evil.com"),
        _make_dns_event(1, "bad.example.com"),
        _make_dns_event(1, "another.domain.net"),
        _make_dns_event(1, "fourth.domain.net"),  # exceeds _MAX_DOMAINS
    ]
    inds = _extract_indicators(raw_eve, correlated)
    domains = [i.value for i in inds if i.type is IndicatorType.DOMAIN]
    assert len(domains) == 3  # capped at _MAX_DOMAINS
    assert "evil.com" in domains


def test_extract_indicators_skips_arpa() -> None:
    raw_eve = {"src_ip": "10.0.0.5"}
    correlated = [_make_dns_event(1, "45.101.220.185.in-addr.arpa")]
    inds = _extract_indicators(raw_eve, correlated)
    assert not any(i.value.endswith(".arpa") for i in inds)


def test_extract_indicators_no_duplicate_ips() -> None:
    raw_eve = {"src_ip": "10.0.0.5", "dest_ip": "10.0.0.5"}
    inds = _extract_indicators(raw_eve, [])
    ip_inds = [i for i in inds if i.type is IndicatorType.IP]
    assert len(ip_inds) == 1


# ---------------------------------------------------------------------------
# TriageWorker integration tests
# ---------------------------------------------------------------------------


def _make_worker(
    event_store: SQLiteEventStore,
    op_store: SQLiteOperationalStore,
    llm: MagicMock,
    config: SuricataConfig,
    daily_cap: int = 300,
) -> TriageWorker:
    return TriageWorker(
        event_store=event_store,
        operational_store=op_store,
        llm=llm,
        suricata_config=config,
        daily_cap=daily_cap,
    )


async def test_process_alert_end_to_end(
    event_store: SQLiteEventStore,
    op_store: SQLiteOperationalStore,
    mock_llm: MagicMock,
    suricata_config: SuricataConfig,
) -> None:
    """Full pipeline: insert alert → process → verdict persisted, status 'analyzed'."""
    worker = _make_worker(event_store, op_store, mock_llm, suricata_config)

    alert_id = await event_store.insert_alert(_make_alert_eve(), status="queued")

    # Dequeue and process.
    alert = (await event_store.query_alerts(status="queued", limit=1))[0]
    await worker._process_alert(alert)

    # Verdict must be persisted.
    verdict = await op_store.get_current_verdict_for_alert(alert_id)
    assert verdict is not None
    assert verdict["verdict_category"] == "likely_fp"
    assert verdict["confidence_score"] == pytest.approx(0.85)

    # Alert status must be 'analyzed' and verdict_id linked.
    updated = await event_store.get_alert(alert_id)
    assert updated["status"] == "analyzed"
    assert updated["verdict_id"] == verdict["verdict_id"]
    assert updated["auto_analyzed"] is True


async def test_process_alert_persists_evidence_chain(
    event_store: SQLiteEventStore,
    op_store: SQLiteOperationalStore,
    mock_llm: MagicMock,
    suricata_config: SuricataConfig,
) -> None:
    worker = _make_worker(event_store, op_store, mock_llm, suricata_config)
    alert_id = await event_store.insert_alert(_make_alert_eve(flow_id=99), status="queued")

    # Insert a correlated DNS event.
    await event_store.insert_eve_event(_make_dns_event(99, "malware.example.com"))

    alert = (await event_store.query_alerts(status="queued", limit=1))[0]
    await worker._process_alert(alert)

    verdict = await op_store.get_current_verdict_for_alert(alert_id)
    chain = json.loads(verdict["evidence_chain"])
    assert "alert" in chain
    assert "role_assignment" in chain
    assert "enrichment_ledger" in chain
    assert "identity" in chain


async def test_process_alert_marks_failed_on_llm_error(
    event_store: SQLiteEventStore,
    op_store: SQLiteOperationalStore,
    suricata_config: SuricataConfig,
) -> None:
    """If the LLM raises, the alert should be marked 'failed'."""
    bad_llm = MagicMock()
    bad_llm.model_version = "gemma4:test"
    bad_llm.complete = AsyncMock(side_effect=RuntimeError("LLM unavailable"))

    worker = _make_worker(event_store, op_store, bad_llm, suricata_config)
    alert_id = await event_store.insert_alert(_make_alert_eve(), status="queued")
    alert = (await event_store.query_alerts(status="queued", limit=1))[0]

    await worker._process_alert(alert)

    updated = await event_store.get_alert(alert_id)
    assert updated["status"] == "failed"
    # No verdict should have been persisted.
    assert await op_store.get_current_verdict_for_alert(alert_id) is None


async def test_dequeue_respects_daily_cap(
    event_store: SQLiteEventStore,
    op_store: SQLiteOperationalStore,
    mock_llm: MagicMock,
    suricata_config: SuricataConfig,
) -> None:
    """When the daily cap is already reached, _dequeue_next returns None."""
    worker = _make_worker(event_store, op_store, mock_llm, suricata_config, daily_cap=0)
    await event_store.insert_alert(_make_alert_eve(), status="queued")
    result = await worker._dequeue_next()
    assert result is None


async def test_dequeue_returns_none_when_queue_empty(
    event_store: SQLiteEventStore,
    op_store: SQLiteOperationalStore,
    mock_llm: MagicMock,
    suricata_config: SuricataConfig,
) -> None:
    worker = _make_worker(event_store, op_store, mock_llm, suricata_config)
    result = await worker._dequeue_next()
    assert result is None


async def test_process_alert_with_vt_enrichment(
    event_store: SQLiteEventStore,
    op_store: SQLiteOperationalStore,
    mock_llm: MagicMock,
    suricata_config: SuricataConfig,
) -> None:
    """Enrichment results from a mock VT client are stored in the evidence chain."""
    mock_vt = MagicMock()
    mock_vt._source = "virustotal"
    mock_vt.lookup = AsyncMock(return_value=EnrichmentResult(
        source="virustotal",
        status=EnrichmentStatus.CONTRIBUTED,
        data={"malicious_count": 25, "total_engines": 90},
        summary="25/90 vendors flagged malicious",
        failure_reason=None,
        failure_detail=None,
        last_success_at=None,
        cached=False,
    ))

    worker = TriageWorker(
        event_store=event_store,
        operational_store=op_store,
        llm=mock_llm,
        suricata_config=suricata_config,
        vt_client=mock_vt,
    )

    alert_id = await event_store.insert_alert(_make_alert_eve(), status="queued")
    alert = (await event_store.query_alerts(status="queued", limit=1))[0]
    await worker._process_alert(alert)

    verdict = await op_store.get_current_verdict_for_alert(alert_id)
    chain = json.loads(verdict["evidence_chain"])
    ledger = chain["enrichment_ledger"]
    contributed = [e for e in ledger if e["status"] == "contributed"]
    assert len(contributed) > 0


async def test_role_assignment_persisted(
    event_store: SQLiteEventStore,
    op_store: SQLiteOperationalStore,
    mock_llm: MagicMock,
    suricata_config: SuricataConfig,
) -> None:
    """After processing, the alert row should have role assignment columns set."""
    worker = _make_worker(event_store, op_store, mock_llm, suricata_config)
    alert_id = await event_store.insert_alert(_make_alert_eve(), status="queued")
    alert = (await event_store.query_alerts(status="queued", limit=1))[0]
    await worker._process_alert(alert)

    updated = await event_store.get_alert(alert_id)
    # initiator_role stores the initiator IP.
    assert updated["initiator_role"] is not None
    assert updated["role_assignment_confidence"] is not None


# ---------------------------------------------------------------------------
# EveCleanupTask tests
# ---------------------------------------------------------------------------


async def test_cleanup_deletes_expired_events(
    event_store: SQLiteEventStore,
) -> None:
    """run_once() should delete old EVE events and return the count."""
    from datetime import timedelta

    old_ts = (datetime.now(UTC) - timedelta(days=10)).isoformat()
    old_event = {
        "timestamp": old_ts,
        "flow_id": 1,
        "event_type": "dns",
        "dns": {"rrname": "old.example.com"},
    }
    await event_store.insert_eve_event(old_event)

    task = EveCleanupTask(event_store, retention_days=7)
    deleted = await task.run_once()
    assert deleted == 1


async def test_cleanup_preserves_recent_events(
    event_store: SQLiteEventStore,
) -> None:
    fresh_event = {
        "timestamp": datetime.now(UTC).isoformat(),
        "flow_id": 2,
        "event_type": "http",
        "http": {},
    }
    await event_store.insert_eve_event(fresh_event)

    task = EveCleanupTask(event_store, retention_days=7)
    deleted = await task.run_once()
    assert deleted == 0
