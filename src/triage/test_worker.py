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
import sqlalchemy as sa
from structlog.contextvars import get_contextvars, merge_contextvars
from structlog.testing import capture_logs

from src.enrichment.models import (
    EnrichmentResult,
    EnrichmentStatus,
    IndicatorType,
)
from src.infra.db.event_store import SQLiteEventStore
from src.infra.db.models import Alert
from src.infra.db.operational_store import SQLiteOperationalStore
from src.infra.db.session import close_db, get_session, init_db
from src.infra.suricata_config.models import SuricataConfig
from src.llm.models import LLMResponse
from src.triage.cleanup import EveCleanupTask
from src.triage.worker import TriageWorker, _extract_indicators, _is_public_ip

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
# Internal names and addresses never reach VT/RDAP
# ---------------------------------------------------------------------------

# 45.10.20.0/24 stands in for a public range the customer owns. It must be
# genuinely global: the RFC 5737 documentation ranges are is_private in
# Python's ipaddress and would pass these tests for the wrong reason.
_PUBLIC_HOME_NET = "45.10.20.0/24"


def _config_with_home_net(*cidrs: str) -> SuricataConfig:
    return SuricataConfig(
        home_net=[ipaddress.ip_network(c) for c in cidrs],
        external_net=[],
        server_groups={},
        port_groups={},
        rule_file_paths=[],
        rule_file_summaries={},
        config_file_paths_read=[],
        read_at=datetime.now(UTC),
        raw_yaml_hash="test",
    )


def _make_tls_event(flow_id: int, sni: str, **endpoints: str) -> dict:
    return {"flow_id": flow_id, "event_type": "tls", "tls": {"sni": sni}, **endpoints}


def _make_http_event(flow_id: int, hostname: str, **endpoints: str) -> dict:
    return {
        "flow_id": flow_id, "event_type": "http", "http": {"hostname": hostname}, **endpoints,
    }


def _make_dns_v3_answer(flow_id: int, domain: str, *rdata: str) -> dict:
    """Suricata 8.x (dns.version 3) shape: query name and answers nested."""
    return {
        "flow_id": flow_id,
        "event_type": "dns",
        "dns": {
            "version": 3,
            "type": "response",
            "queries": [{"rrname": domain, "rrtype": "A"}],
            "answers": [{"rrname": domain, "rrtype": "A", "rdata": r} for r in rdata],
        },
    }


def _domains(inds: list) -> list[str]:
    return [i.value for i in inds if i.type is IndicatorType.DOMAIN]


def test_extract_indicators_skips_nas_local() -> None:
    raw_eve = {"src_ip": "10.0.0.5", "dest_ip": "10.0.0.9"}
    inds = _extract_indicators(raw_eve, [_make_tls_event(1, "nas.local")])
    assert _domains(inds) == []


def test_extract_indicators_skips_fileserver_corp() -> None:
    raw_eve = {"src_ip": "10.0.0.5", "dest_ip": "10.0.0.9"}
    inds = _extract_indicators(raw_eve, [_make_dns_event(1, "fileserver.corp")])
    assert _domains(inds) == []


@pytest.mark.parametrize("name", [
    "printer.lan",
    "wiki.internal",
    "router.home",
    "nas.home.arpa",
    "box.localdomain",
    "NAS.LOCAL",
    "fileserver.corp.",
])
def test_extract_indicators_skips_internal_suffixes(name: str) -> None:
    inds = _extract_indicators({"src_ip": "10.0.0.5"}, [_make_dns_event(1, name)])
    assert _domains(inds) == []


def test_extract_indicators_keeps_names_that_only_contain_internal_words() -> None:
    """Suffix match only: a public name containing 'corp' or 'local' is kept."""
    correlated = [
        _make_dns_event(1, "corp.example.com"),
        _make_dns_event(1, "localnews.com"),
        _make_dns_event(1, "evil.corporation"),
    ]
    inds = _extract_indicators({"src_ip": "10.0.0.5"}, correlated)
    assert _domains(inds) == ["corp.example.com", "localnews.com", "evil.corporation"]


def test_extract_indicators_skips_domain_resolving_to_home_net() -> None:
    config = _config_with_home_net("10.0.0.0/8")
    correlated = [
        _make_http_event(1, "intranet.acme.com"),
        _make_dns_v3_answer(1, "intranet.acme.com", "10.20.30.40"),
    ]
    inds = _extract_indicators({"src_ip": "10.0.0.5"}, correlated, config)
    assert _domains(inds) == []


def test_extract_indicators_skips_domain_resolving_to_public_home_net() -> None:
    config = _config_with_home_net("10.0.0.0/8", _PUBLIC_HOME_NET)
    correlated = [_make_dns_v3_answer(1, "portal.acme.com", "45.10.20.7")]
    inds = _extract_indicators({"src_ip": "10.0.0.5"}, correlated, config)
    assert _domains(inds) == []


def test_extract_indicators_keeps_domain_resolving_outside_home_net() -> None:
    config = _config_with_home_net("10.0.0.0/8")
    correlated = [_make_dns_v3_answer(1, "evil.example.com", "185.220.101.45")]
    inds = _extract_indicators({"src_ip": "10.0.0.5"}, correlated, config)
    assert _domains(inds) == ["evil.example.com"]


def test_extract_indicators_home_net_answer_via_cname_chain() -> None:
    """A CNAME in front of the HOME_NET A record must not hide it."""
    config = _config_with_home_net("10.0.0.0/8")
    event = {
        "flow_id": 1,
        "event_type": "dns",
        "dns": {
            "version": 3,
            "type": "response",
            "queries": [{"rrname": "intranet.acme.com", "rrtype": "A"}],
            "answers": [
                {"rrname": "intranet.acme.com", "rrtype": "CNAME", "rdata": "lb.acme.com"},
                {"rrname": "lb.acme.com", "rrtype": "A", "rdata": "10.1.1.1"},
            ],
        },
    }
    inds = _extract_indicators({"src_ip": "10.0.0.5"}, [event], config)
    assert _domains(inds) == []


def test_extract_indicators_home_net_answer_grouped_and_per_record_shapes() -> None:
    config = _config_with_home_net("10.0.0.0/8")
    grouped = {
        "flow_id": 1,
        "event_type": "dns",
        "dns": {"type": "answer", "rrname": "git.acme.com", "grouped": {"A": ["10.9.9.9"]}},
    }
    per_record = {
        "flow_id": 1,
        "event_type": "dns",
        "dns": {"type": "answer", "rrname": "jira.acme.com", "rrtype": "A", "rdata": "10.8.8.8"},
    }
    inds = _extract_indicators({"src_ip": "10.0.0.5"}, [grouped, per_record], config)
    assert _domains(inds) == []


def test_extract_indicators_skips_http_hostname_on_home_net_server() -> None:
    """intranet.acme.com over HTTP, no DNS event on the flow: server IP decides."""
    config = _config_with_home_net("10.0.0.0/8")
    correlated = [
        _make_http_event(1, "intranet.acme.com", src_ip="10.0.0.5", dest_ip="10.20.30.40"),
    ]
    inds = _extract_indicators({"src_ip": "10.0.0.5"}, correlated, config)
    assert _domains(inds) == []


def test_extract_indicators_skips_tls_sni_on_home_net_server() -> None:
    """intranet.acme.com over TLS, no DNS event on the flow: server IP decides."""
    config = _config_with_home_net("10.0.0.0/8")
    correlated = [
        _make_tls_event(1, "intranet.acme.com", src_ip="10.0.0.5", dest_ip="10.20.30.40"),
    ]
    inds = _extract_indicators({"src_ip": "10.0.0.5"}, correlated, config)
    assert _domains(inds) == []


def test_extract_indicators_skips_sni_on_public_home_net_server() -> None:
    config = _config_with_home_net("10.0.0.0/8", _PUBLIC_HOME_NET)
    correlated = [_make_tls_event(1, "portal.acme.com", src_ip="10.0.0.5", dest_ip="45.10.20.7")]
    inds = _extract_indicators({"src_ip": "10.0.0.5"}, correlated, config)
    assert _domains(inds) == []


def test_extract_indicators_keeps_external_server_with_internal_client() -> None:
    """The common case: an internal client talking out. The client side must not decide."""
    config = _config_with_home_net("10.0.0.0/8")
    correlated = [
        _make_http_event(1, "evil.example.com", src_ip="10.0.0.5", dest_ip="185.220.101.45"),
        _make_tls_event(1, "c2.example.net", src_ip="10.0.0.5", dest_ip="185.220.101.46"),
    ]
    inds = _extract_indicators({"src_ip": "10.0.0.5"}, correlated, config)
    assert _domains(inds) == ["evil.example.com", "c2.example.net"]


def test_extract_indicators_keeps_high_port_external_server() -> None:
    """Server on a high port (corpus: gammaproject.dev:59619). No port-based side guessing."""
    config = _config_with_home_net("10.0.0.0/8")
    event = _make_http_event(1, "gammaproject.dev", src_ip="10.0.0.5", dest_ip="185.220.101.45")
    event.update(src_port=51937, dest_port=59619)
    inds = _extract_indicators({"src_ip": "10.0.0.5"}, [event], config)
    assert _domains(inds) == ["gammaproject.dev"]


def test_extract_indicators_to_client_direction_uses_src_as_server() -> None:
    config = _config_with_home_net("10.0.0.0/8")
    internal_server = _make_tls_event(
        1, "intranet.acme.com", src_ip="10.20.30.40", dest_ip="10.0.0.5", direction="to_client",
    )
    external_server = _make_tls_event(
        1, "evil.example.com", src_ip="185.220.101.45", dest_ip="10.0.0.5", direction="to_client",
    )
    inds = _extract_indicators({"src_ip": "10.0.0.5"}, [internal_server, external_server], config)
    assert _domains(inds) == ["evil.example.com"]


def test_extract_indicators_dns_resolver_address_does_not_drop_name() -> None:
    """A dns event's dest_ip is the resolver, usually internal. It must not drop the name."""
    config = _config_with_home_net("10.0.0.0/8")
    event = _make_dns_event(1, "evil.example.com")
    event.update(src_ip="10.0.0.5", dest_ip="10.0.0.53")
    inds = _extract_indicators({"src_ip": "10.0.0.5"}, [event], config)
    assert _domains(inds) == ["evil.example.com"]


def test_extract_indicators_without_config_skips_suffixes_only() -> None:
    """With no config there is no HOME_NET to check; suffix filtering still applies."""
    correlated = [
        _make_tls_event(1, "nas.local"),
        _make_dns_v3_answer(1, "intranet.acme.com", "10.20.30.40"),
    ]
    inds = _extract_indicators({"src_ip": "10.0.0.5"}, correlated)
    assert _domains(inds) == ["intranet.acme.com"]


def test_extract_indicators_skipped_names_do_not_use_domain_cap() -> None:
    correlated = [
        _make_dns_event(1, "a.local"),
        _make_dns_event(1, "b.corp"),
        _make_dns_event(1, "c.lan"),
        _make_dns_event(1, "one.com"),
        _make_dns_event(1, "two.com"),
        _make_dns_event(1, "three.com"),
    ]
    inds = _extract_indicators({"src_ip": "10.0.0.5"}, correlated)
    assert _domains(inds) == ["one.com", "two.com", "three.com"]


def test_is_public_ip_rejects_cgnat() -> None:
    assert _is_public_ip("100.64.1.1") is False
    assert _is_public_ip("100.127.255.254") is False
    # Boundaries of 100.64.0.0/10 stay public.
    assert _is_public_ip("100.63.255.255") is True
    assert _is_public_ip("100.128.0.1") is True


def test_is_public_ip_rejects_public_home_net() -> None:
    config = _config_with_home_net("10.0.0.0/8", _PUBLIC_HOME_NET)
    assert _is_public_ip("45.10.20.7", config) is False
    assert _is_public_ip("45.10.20.7") is True  # no config → no HOME_NET check
    assert _is_public_ip("185.220.101.45", config) is True


def test_is_public_ip_home_net_any_filters_nothing_extra() -> None:
    """HOME_NET 'any' parses to an empty list, so no address counts as HOME_NET."""
    config = _config_with_home_net()
    assert _is_public_ip("185.220.101.45", config) is True
    assert _is_public_ip("10.0.0.5", config) is False  # still private


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


async def test_context_not_leaked_between_alerts(
    event_store: SQLiteEventStore,
    op_store: SQLiteOperationalStore,
    suricata_config: SuricataConfig,
) -> None:
    """bind_alert_context()/clear_alert_context() must not leak alert_id
    across alerts -- a first alert that raises must not leave its alert_id
    bound to contextvars merged into a second, successful alert's log lines.
    A leak here would make alert_id-based log correlation actively
    misleading -- exactly the diagnosis this wiring exists to enable."""
    bad_llm = MagicMock()
    bad_llm.model_version = "gemma4:test"
    bad_llm.complete = AsyncMock(side_effect=RuntimeError("LLM unavailable"))

    worker_a = _make_worker(event_store, op_store, bad_llm, suricata_config)
    alert_id_a = await event_store.insert_alert(_make_alert_eve(), status="queued")
    alert_a = (await event_store.query_alerts(status="queued", limit=1))[0]
    await worker_a._process_alert(alert_a)

    # Cleared after a *failing* alert too, not just a successful one.
    assert get_contextvars() == {}

    good_llm = MagicMock()
    good_llm.model_version = "gemma4:test"
    good_llm.complete = AsyncMock(return_value=LLMResponse(
        verdict_category="likely_fp",
        confidence_score=0.5,
        reasoning="ok",
        contributing_facts=[],
        raw_output={},
        latency_ms=1,
        model_version="gemma4:test",
        prompt_version="verdict_v1",
        llm_inputs={},
        first_attempt_valid=True,
        attempts=1,
    ))
    worker_b = _make_worker(event_store, op_store, good_llm, suricata_config)
    alert_id_b = await event_store.insert_alert(
        _make_alert_eve(src_ip="10.0.0.6"), status="queued"
    )
    alert_b = (await event_store.query_alerts(status="queued", limit=1))[0]

    with capture_logs(processors=[merge_contextvars]) as logs:
        await worker_b._process_alert(alert_b)

    bound_ids = {e["alert_id"] for e in logs if "alert_id" in e}
    assert bound_ids == {alert_id_b}
    assert alert_id_a not in bound_ids


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


async def test_dequeue_returns_oldest_queued_alert_fifo(
    event_store: SQLiteEventStore,
    op_store: SQLiteOperationalStore,
    mock_llm: MagicMock,
    suricata_config: SuricataConfig,
) -> None:
    """ADR-023: FIFO. Three alerts inserted out of chronological order --
    _dequeue_next() must return the oldest by ingest_timestamp, regardless of
    insertion order."""
    worker = _make_worker(event_store, op_store, mock_llm, suricata_config)

    id_middle = await event_store.insert_alert(_make_alert_eve(flow_id=1), status="queued")
    id_oldest = await event_store.insert_alert(_make_alert_eve(flow_id=2), status="queued")
    id_newest = await event_store.insert_alert(_make_alert_eve(flow_id=3), status="queued")

    async with get_session() as session:
        for alert_id, ts in (
            (id_middle, "2026-08-27T12:00:00+00:00"),
            (id_oldest, "2026-08-27T10:00:00+00:00"),
            (id_newest, "2026-08-27T14:00:00+00:00"),
        ):
            await session.execute(
                sa.update(Alert).where(Alert.alert_id == alert_id).values(ingest_timestamp=ts)
            )

    result = await worker._dequeue_next()

    assert result is not None
    assert result["alert_id"] == id_oldest


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


async def test_process_alert_never_sends_internal_indicators(
    event_store: SQLiteEventStore,
    op_store: SQLiteOperationalStore,
    mock_llm: MagicMock,
) -> None:
    """Internal names and addresses reach neither client and get no VT/RDAP ledger entry."""
    config = _config_with_home_net("10.0.0.0/8", _PUBLIC_HOME_NET)

    def _ok(source: str) -> EnrichmentResult:
        return EnrichmentResult(
            source=source,
            status=EnrichmentStatus.CONTRIBUTED,
            data={},
            summary="ok",
            failure_reason=None,
            failure_detail=None,
            last_success_at=None,
            cached=False,
        )

    mock_vt = MagicMock()
    mock_vt.lookup = AsyncMock(return_value=_ok("virustotal"))
    mock_rdap = MagicMock()
    mock_rdap.lookup = AsyncMock(return_value=_ok("rdap"))

    worker = TriageWorker(
        event_store=event_store,
        operational_store=op_store,
        llm=mock_llm,
        suricata_config=config,
        vt_client=mock_vt,
        rdap_client=mock_rdap,
    )

    # Victim is a public address inside HOME_NET; attacker is external.
    alert_id = await event_store.insert_alert(
        _make_alert_eve(flow_id=77, src_ip="185.220.101.45", dest_ip="45.10.20.7"),
        status="queued",
    )
    for ev in (
        _make_tls_event(77, "nas.local"),
        _make_dns_event(77, "fileserver.corp"),
        _make_http_event(77, "intranet.acme.com"),
        _make_dns_v3_answer(77, "intranet.acme.com", "10.20.30.40"),
        _make_tls_event(77, "wiki.acme.com", src_ip="185.220.101.45", dest_ip="10.5.5.5"),
        _make_tls_event(77, "evil.example.com"),
    ):
        await event_store.insert_eve_event(ev)

    alert = (await event_store.query_alerts(status="queued", limit=1))[0]
    await worker._process_alert(alert)

    sent_to_vt = {c.args[0].value for c in mock_vt.lookup.call_args_list}
    sent_to_rdap = {c.args[0].value for c in mock_rdap.lookup.call_args_list}
    assert sent_to_vt == {"185.220.101.45", "evil.example.com"}
    assert sent_to_rdap == {"evil.example.com"}

    verdict = await op_store.get_current_verdict_for_alert(alert_id)
    assert verdict is not None
    ledger = json.loads(verdict["evidence_chain"])["enrichment_ledger"]
    external_sources = {
        e["indicator"] for e in ledger if e["source"] in ("virustotal", "rdap")
    }
    assert external_sources == {"185.220.101.45", "evil.example.com"}


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
# Dedup / inheritance — ADR-022
# ---------------------------------------------------------------------------


async def test_dedup_second_in_group_inherits(
    event_store: SQLiteEventStore,
    op_store: SQLiteOperationalStore,
    mock_llm: MagicMock,
    suricata_config: SuricataConfig,
) -> None:
    """Two sequential same-group alerts: the second inherits the first's verdict."""
    worker = _make_worker(event_store, op_store, mock_llm, suricata_config)

    alert_a = await event_store.insert_alert(_make_alert_eve(flow_id=1), status="queued")
    alert_b = await event_store.insert_alert(_make_alert_eve(flow_id=2), status="queued")

    await worker._process_alert(await event_store.get_alert(alert_a))
    await worker._process_alert(await event_store.get_alert(alert_b))

    verdict_b = await op_store.get_current_verdict_for_alert(alert_b)
    assert verdict_b["latency_ms"] == 0
    assert json.loads(verdict_b["llm_inputs"]).get("inherited_from")


async def test_dedup_third_in_group_inherits_from_original_producer(
    event_store: SQLiteEventStore,
    op_store: SQLiteOperationalStore,
    mock_llm: MagicMock,
    suricata_config: SuricataConfig,
) -> None:
    """ADR-022 DECIDE 1: one hop only — but reaching past an inherited sibling to
    a produced source is still one hop, not a chain.

    A (first in group) is analyzed and produces a verdict. B (same group)
    inherits from A. C (same group) must skip B — B is itself an inherited
    verdict, and DECIDE 1 forbids chaining *through* it — and inherit directly
    from A instead. C is not analyzed individually and does not chain off B.
    """
    worker = _make_worker(event_store, op_store, mock_llm, suricata_config)

    alert_a = await event_store.insert_alert(_make_alert_eve(flow_id=1), status="queued")
    alert_b = await event_store.insert_alert(_make_alert_eve(flow_id=2), status="queued")
    alert_c = await event_store.insert_alert(_make_alert_eve(flow_id=3), status="queued")

    await worker._process_alert(await event_store.get_alert(alert_a))
    await worker._process_alert(await event_store.get_alert(alert_b))
    await worker._process_alert(await event_store.get_alert(alert_c))

    verdict_a = await op_store.get_current_verdict_for_alert(alert_a)
    verdict_b = await op_store.get_current_verdict_for_alert(alert_b)
    verdict_c = await op_store.get_current_verdict_for_alert(alert_c)

    # A: produced.
    assert "inherited_from" not in json.loads(verdict_a["llm_inputs"])

    # B: inherited from A — sets up the boundary case DECIDE 1 governs.
    assert json.loads(verdict_b["llm_inputs"]).get("inherited_from") == verdict_a["verdict_id"]

    # C: inherits from A specifically — reaches past B rather than chaining
    # through it or falling back to a full individual analysis.
    assert json.loads(verdict_c["llm_inputs"]).get("inherited_from") == verdict_a["verdict_id"]
    assert verdict_c["latency_ms"] == 0


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
