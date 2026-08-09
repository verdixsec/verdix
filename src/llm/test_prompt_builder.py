# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Tests for PromptBuilder and enrichment context helpers."""
from __future__ import annotations

import pytest

from src.enrichment.maxmind.client import _SOURCE as _GEOIP_SOURCE
from src.enrichment.models import EnrichmentResult, EnrichmentStatus, Indicator, IndicatorType
from src.enrichment.rdap.client import _SOURCE as _RDAP_SOURCE
from src.enrichment.virustotal.client import _SOURCE as _VT_SOURCE
from src.llm.prompt_builder import (
    PromptBuilder,
    build_enrichment_context,
    eval_enrichment_context_from_hits,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def minimal_alert() -> dict:
    return {
        "timestamp": "2026-01-01T00:00:00.000000+0000",
        "flow_id": 123,
        "event_type": "alert",
        "src_ip": "10.0.0.5",
        "src_port": 49152,
        "dest_ip": "1.2.3.4",
        "dest_port": 443,
        "proto": "TCP",
        "app_proto": "tls",
        "alert": {
            "signature": "ET MALWARE FormBook CnC Checkin",
            "signature_id": 2025553,
            "severity": 1,
            "category": "A Network Trojan was Detected",
            "metadata": None,
        },
        "tls": {"sni": "evil.example.com", "subject": "CN=evil.example.com"},
    }


@pytest.fixture()
def vt_contributed_result() -> EnrichmentResult:
    return EnrichmentResult(
        source="virustotal",
        status=EnrichmentStatus.CONTRIBUTED,
        data={"malicious_count": 15, "total_engines": 72},
        summary="15/72 vendors flagged malicious",
        failure_reason=None,
        failure_detail=None,
        last_success_at=None,
    )


@pytest.fixture()
def vt_not_configured_result() -> EnrichmentResult:
    return EnrichmentResult.not_configured("virustotal")


# ---------------------------------------------------------------------------
# build_enrichment_context
# ---------------------------------------------------------------------------

class TestBuildEnrichmentContext:
    def test_contributed_ip_sets_vt_fields(self, vt_contributed_result):
        indicator = Indicator(type=IndicatorType.IP, value="1.2.3.4")
        ctx = build_enrichment_context([(indicator, vt_contributed_result)])
        assert len(ctx) == 1
        item = ctx[0]
        assert item["type"] == "ip"
        assert item["indicator"] == "1.2.3.4"
        assert item["source"] == "VirusTotal"
        assert item["status"] == "contributed"
        assert item["vt_malicious"] == 15
        assert item["vt_total"] == 72
        assert "malicious" in item["label"].lower()

    def test_not_configured_included_without_vt_fields(self, vt_not_configured_result):
        indicator = Indicator(type=IndicatorType.IP, value="1.2.3.4")
        ctx = build_enrichment_context([(indicator, vt_not_configured_result)])
        assert len(ctx) == 1
        item = ctx[0]
        assert item["status"] == "not_configured"
        assert "vt_malicious" not in item
        assert "vt_total" not in item

    def test_cached_result_sets_cache_fields(self, vt_contributed_result):
        vt_contributed_result.cached = True
        vt_contributed_result.cache_age_seconds = 300
        indicator = Indicator(type=IndicatorType.IP, value="1.2.3.4")
        ctx = build_enrichment_context([(indicator, vt_contributed_result)])
        assert ctx[0]["cached"] is True
        assert ctx[0]["cache_age_seconds"] == 300

    def test_domain_indicator_type(self):
        result = EnrichmentResult(
            source="virustotal",
            status=EnrichmentStatus.CONTRIBUTED,
            data={"malicious_count": 0, "total_engines": 70},
            summary="clean",
            failure_reason=None,
            failure_detail=None,
            last_success_at=None,
        )
        indicator = Indicator(type=IndicatorType.DOMAIN, value="example.com")
        ctx = build_enrichment_context([(indicator, result)])
        assert ctx[0]["type"] == "domain"
        assert "clean" in ctx[0]["label"].lower()

    def test_vt_label_confirmed_malicious(self, vt_contributed_result):
        indicator = Indicator(type=IndicatorType.IP, value="1.2.3.4")
        ctx = build_enrichment_context([(indicator, vt_contributed_result)])
        assert "confirmed malicious" in ctx[0]["label"].lower()

    def test_vt_label_suspicious_low_count(self):
        result = EnrichmentResult(
            source="virustotal",
            status=EnrichmentStatus.CONTRIBUTED,
            data={"malicious_count": 3, "total_engines": 70},
            summary="3/70",
            failure_reason=None,
            failure_detail=None,
            last_success_at=None,
        )
        indicator = Indicator(type=IndicatorType.IP, value="5.5.5.5")
        ctx = build_enrichment_context([(indicator, result)])
        assert "suspicious" in ctx[0]["label"].lower()

    def test_vt_label_not_in_database(self):
        result = EnrichmentResult(
            source="virustotal",
            status=EnrichmentStatus.CONTRIBUTED,
            data={"malicious_count": 0, "total_engines": 0, "not_in_database": True},
            summary="not in db",
            failure_reason=None,
            failure_detail=None,
            last_success_at=None,
        )
        indicator = Indicator(type=IndicatorType.DOMAIN, value="newdomain.xyz")
        ctx = build_enrichment_context([(indicator, result)])
        assert "not in virustotal" in ctx[0]["label"].lower()

    def test_multiple_indicators(self, vt_contributed_result, vt_not_configured_result):
        pairs = [
            (Indicator(type=IndicatorType.IP, value="1.1.1.1"), vt_contributed_result),
            (Indicator(type=IndicatorType.DOMAIN, value="evil.example"), vt_not_configured_result),
        ]
        ctx = build_enrichment_context(pairs)
        assert len(ctx) == 2
        assert ctx[0]["status"] == "contributed"
        assert ctx[1]["status"] == "not_configured"


# ---------------------------------------------------------------------------
# _source_display (via build_enrichment_context)
# ---------------------------------------------------------------------------

class TestSourceDisplay:
    """Every live ThreatIntelProvider source key must resolve to a display name.

    Regression guard: when GeoIPClient's source key changed from "maxmind" to
    "geoip", the prompt_builder display map wasn't updated, so the LLM's
    enrichment-source ledger silently showed the raw key "geoip" instead of a
    label. Importing each client's real _SOURCE constant means a future
    provider swap fails this test instead of reintroducing that bug.
    """

    @pytest.mark.parametrize(
        "source_key",
        [
            pytest.param(_VT_SOURCE, id="virustotal"),
            pytest.param(_RDAP_SOURCE, id="rdap"),
            pytest.param(_GEOIP_SOURCE, id="geoip"),
        ],
    )
    def test_live_source_key_has_display_name(self, source_key):
        indicator = Indicator(type=IndicatorType.IP, value="1.2.3.4")
        result = EnrichmentResult.not_configured(source_key)
        ctx = build_enrichment_context([(indicator, result)])
        assert ctx[0]["source"] != source_key, (
            f"no display name mapped for live source key {source_key!r} — "
            "add it to _source_display()'s _DISPLAY dict in prompt_builder.py"
        )


# ---------------------------------------------------------------------------
# eval_enrichment_context_from_hits
# ---------------------------------------------------------------------------

class TestEvalEnrichmentContextFromHits:
    def test_basic_hit_conversion(self):
        class FakeHit:
            type = "ip"
            indicator = "1.2.3.4"
            label = "Confirmed malicious"
            vt_malicious = 20
            vt_total = 80

        ctx = eval_enrichment_context_from_hits([FakeHit()])
        assert len(ctx) == 1
        item = ctx[0]
        assert item["type"] == "ip"
        assert item["indicator"] == "1.2.3.4"
        assert item["source"] == "VirusTotal"
        assert item["status"] == "contributed"
        assert item["vt_malicious"] == 20
        assert item["vt_total"] == 80
        assert item["cached"] is False
        assert item["failure_reason"] is None

    def test_empty_list(self):
        ctx = eval_enrichment_context_from_hits([])
        assert ctx == []


# ---------------------------------------------------------------------------
# PromptBuilder
# ---------------------------------------------------------------------------

class TestPromptBuilder:
    def test_renders_signature(self, minimal_alert):
        builder = PromptBuilder()
        prompt = builder.build(alert=minimal_alert)
        assert "FormBook CnC Checkin" in prompt

    def test_renders_alert_metadata(self, minimal_alert):
        builder = PromptBuilder()
        prompt = builder.build(alert=minimal_alert)
        assert "10.0.0.5" in prompt
        assert "1.2.3.4" in prompt
        assert "2025553" in prompt

    def test_no_enrichment_shows_no_hits_message(self, minimal_alert):
        builder = PromptBuilder()
        prompt = builder.build(alert=minimal_alert, enrichment_context=[])
        assert "No threat intelligence hits" in prompt

    def test_contributed_enrichment_rendered(self, minimal_alert):
        builder = PromptBuilder()
        enrichment_ctx = [
            {
                "type": "ip",
                "indicator": "1.2.3.4",
                "source": "VirusTotal",
                "status": "contributed",
                "label": "Confirmed malicious — 15/72 vendors",
                "vt_malicious": 15,
                "vt_total": 72,
                "summary": "15/72 vendors flagged malicious",
                "cached": False,
                "cache_age_seconds": None,
                "failure_reason": None,
            }
        ]
        prompt = builder.build(alert=minimal_alert, enrichment_context=enrichment_ctx)
        assert "Confirmed malicious" in prompt
        assert "15/72" in prompt

    def test_not_configured_shows_ledger_entry(self, minimal_alert):
        builder = PromptBuilder()
        enrichment_ctx = [
            {
                "type": "ip",
                "indicator": "1.2.3.4",
                "source": "VirusTotal",
                "status": "not_configured",
                "summary": None,
                "cached": False,
                "cache_age_seconds": None,
                "failure_reason": None,
            }
        ]
        prompt = builder.build(alert=minimal_alert, enrichment_context=enrichment_ctx)
        assert "NOT_CONFIGURED" in prompt
        assert "VirusTotal" in prompt

    def test_tls_sni_rendered(self, minimal_alert):
        builder = PromptBuilder()
        prompt = builder.build(alert=minimal_alert)
        assert "evil.example.com" in prompt

    def test_correlated_alert_rendered(self, minimal_alert):
        builder = PromptBuilder()
        co_alert = {
            "event_type": "alert",
            "alert": {
                "signature": "ET MALWARE CnC Beacon",
                "signature_id": 9999999,
                "category": "Malware Command and Control Activity Detected",
                "severity": 1,
            },
        }
        prompt = builder.build(alert=minimal_alert, correlated_events=[co_alert])
        assert "CO-ALERT" in prompt
        assert "CnC Beacon" in prompt

    def test_no_correlated_shows_none_message(self, minimal_alert):
        builder = PromptBuilder()
        prompt = builder.build(alert=minimal_alert, correlated_events=[])
        assert "No correlated context events" in prompt

    def test_prompt_version_attribute(self):
        builder = PromptBuilder()
        assert builder.prompt_version == "verdict_v3"

    def test_custom_prompt_version_raises_on_missing_template(self):
        import jinja2
        builder = PromptBuilder(prompt_version="nonexistent_v99")
        with pytest.raises(jinja2.TemplateNotFound):
            builder.build(alert={"alert": {}, "timestamp": "x"})

    def test_cached_result_shows_cache_age(self, minimal_alert):
        builder = PromptBuilder()
        enrichment_ctx = [
            {
                "type": "ip",
                "indicator": "1.2.3.4",
                "source": "VirusTotal",
                "status": "contributed",
                "label": "Confirmed malicious — 15/72 vendors",
                "vt_malicious": 15,
                "vt_total": 72,
                "summary": "cached",
                "cached": True,
                "cache_age_seconds": 600,
                "failure_reason": None,
            }
        ]
        prompt = builder.build(alert=minimal_alert, enrichment_context=enrichment_ctx)
        assert "cached" in prompt.lower()
        assert "600" in prompt

    def test_reusable_across_calls(self, minimal_alert):
        builder = PromptBuilder()
        p1 = builder.build(alert=minimal_alert)
        p2 = builder.build(alert=minimal_alert)
        assert p1 == p2
