# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Tests for PromptBuilder and enrichment context helpers."""
from __future__ import annotations

import hashlib

import pytest

from src.domain.flow_context import build_flow_context
from src.enrichment.maxmind.client import _SOURCE as _GEOIP_SOURCE
from src.enrichment.models import (
    EnrichmentResult,
    EnrichmentStatus,
    FailureReason,
    Indicator,
    IndicatorType,
)
from src.enrichment.rdap.client import _SOURCE as _RDAP_SOURCE
from src.enrichment.virustotal.client import _SOURCE as _VT_SOURCE
from src.llm.prompt_builder import (
    _PROMPTS_DIR,
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


@pytest.fixture()
def geoip_public_ip_result() -> EnrichmentResult:
    """Real shape from src/enrichment/maxmind/client.py — a public IP with ASN data."""
    return EnrichmentResult(
        source="geoip",
        status=EnrichmentStatus.CONTRIBUTED,
        data={
            "country_code": "LU",
            "country_name": "Luxembourg",
            "asn": 205759,
            "asn_org": "Ghostly Networks LLC",
        },
        summary="LU, AS205759 Ghostly Networks LLC",
        failure_reason=None,
        failure_detail=None,
        last_success_at=None,
    )


@pytest.fixture()
def geoip_private_ip_result() -> EnrichmentResult:
    """Real shape from src/enrichment/maxmind/client.py — the "Private IP" branch."""
    return EnrichmentResult(
        source="geoip",
        status=EnrichmentStatus.CONTRIBUTED,
        data={"note": "private_ip"},
        summary="Private IP",
        failure_reason=None,
        failure_detail=None,
        last_success_at=None,
    )


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

    def test_vt_not_configured_omitted_entirely(self, vt_not_configured_result):
        """Decision table: VT NOT_CONFIGURED -> omit entirely, not a ledger entry.

        The model sees successful lookups only. A source that was never
        configured contributes no information and must not appear at all.
        """
        indicator = Indicator(type=IndicatorType.IP, value="1.2.3.4")
        ctx = build_enrichment_context([(indicator, vt_not_configured_result)])
        assert ctx == []

    def test_vt_failing_omitted_entirely(self):
        """Decision table: VT FAILING -> omit entirely, no failure_reason, no mention."""
        indicator = Indicator(type=IndicatorType.IP, value="1.2.3.4")
        result = EnrichmentResult.failing(
            "virustotal", FailureReason.RATE_LIMITED, "VT rate limit hit"
        )
        ctx = build_enrichment_context([(indicator, result)])
        assert ctx == []

    def test_geoip_not_configured_omitted_entirely(self):
        indicator = Indicator(type=IndicatorType.IP, value="1.2.3.4")
        result = EnrichmentResult.not_configured("geoip")
        ctx = build_enrichment_context([(indicator, result)])
        assert ctx == []

    def test_geoip_failing_omitted_entirely(self):
        indicator = Indicator(type=IndicatorType.IP, value="1.2.3.4")
        result = EnrichmentResult.failing("geoip", FailureReason.OTHER, "mmdb read error")
        ctx = build_enrichment_context([(indicator, result)])
        assert ctx == []

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

    # -----------------------------------------------------------------
    # "VT answered but has no analysis to report" — never a count.
    # not_in_database (404/never-indexed) and an empty last_analysis_stats
    # payload (a 200 with nothing to report) are the same underlying
    # situation and both must render an explicit no-analysis statement,
    # never an n/m count. Distinguishable in wording only.
    # -----------------------------------------------------------------

    def test_vt_not_in_database_has_no_analysis_text_not_a_count(self):
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
        item = ctx[0]
        assert "label" not in item
        assert item["vt_total"] == 0
        assert (
            item["vt_no_analysis_text"]
            == "Not in VirusTotal's database — no analysis data returned."
        )

    def test_vt_empty_stats_has_no_analysis_text_not_a_count(self):
        """A genuine CONTRIBUTED result with empty scan stats and no
        not_in_database flag — the case flagged rather than invented against
        in the prior pass. Same rule applies: never a count."""
        result = EnrichmentResult(
            source="virustotal",
            status=EnrichmentStatus.CONTRIBUTED,
            data={
                "malicious_count": 0,
                "suspicious_count": 0,
                "total_engines": 0,
                "reputation": None,
                "last_analysis_stats": {},
            },
            summary="no scan stats",
            failure_reason=None,
            failure_detail=None,
            last_success_at=None,
        )
        indicator = Indicator(type=IndicatorType.IP, value="9.9.9.9")
        ctx = build_enrichment_context([(indicator, result)])
        item = ctx[0]
        assert "label" not in item
        assert item["vt_total"] == 0
        assert (
            item["vt_no_analysis_text"]
            == "VirusTotal returned no analysis data for this indicator."
        )

    def test_vt_no_analysis_cases_are_distinguishable(self):
        not_in_db = EnrichmentResult(
            source="virustotal",
            status=EnrichmentStatus.CONTRIBUTED,
            data={"malicious_count": 0, "total_engines": 0, "not_in_database": True},
            summary="x",
            failure_reason=None,
            failure_detail=None,
            last_success_at=None,
        )
        empty_stats = EnrichmentResult(
            source="virustotal",
            status=EnrichmentStatus.CONTRIBUTED,
            data={"malicious_count": 0, "total_engines": 0},
            summary="x",
            failure_reason=None,
            failure_detail=None,
            last_success_at=None,
        )
        indicator = Indicator(type=IndicatorType.IP, value="1.2.3.4")
        ctx_not_in_db = build_enrichment_context([(indicator, not_in_db)])
        ctx_empty_stats = build_enrichment_context([(indicator, empty_stats)])
        assert (
            ctx_not_in_db[0]["vt_no_analysis_text"]
            != ctx_empty_stats[0]["vt_no_analysis_text"]
        )

    def test_multiple_indicators_drops_non_contributed(
        self, vt_contributed_result, vt_not_configured_result
    ):
        """Only the contributed result survives; the not-configured one is dropped."""
        pairs = [
            (Indicator(type=IndicatorType.IP, value="1.1.1.1"), vt_contributed_result),
            (Indicator(type=IndicatorType.DOMAIN, value="evil.example"), vt_not_configured_result),
        ]
        ctx = build_enrichment_context(pairs)
        assert len(ctx) == 1
        assert ctx[0]["status"] == "contributed"
        assert ctx[0]["indicator"] == "1.1.1.1"

    # -----------------------------------------------------------------
    # GeoIP is source-aware: never receives VirusTotal's field shape.
    # Regression test for the v0.1.6 defect — a GeoIP CONTRIBUTED result
    # (public or private IP) must never produce vt_malicious/vt_total/label.
    # -----------------------------------------------------------------

    def test_geoip_contributed_public_ip_has_no_vt_fields(self, geoip_public_ip_result):
        indicator = Indicator(type=IndicatorType.IP, value="64.89.161.173")
        ctx = build_enrichment_context([(indicator, geoip_public_ip_result)])
        assert len(ctx) == 1
        item = ctx[0]
        assert item["source"] == "GeoIP"
        assert item["status"] == "contributed"
        assert item["summary"] == "LU, AS205759 Ghostly Networks LLC"
        assert "vt_malicious" not in item
        assert "vt_total" not in item
        assert "label" not in item
        assert "vt_cache_age" not in item

    def test_geoip_contributed_private_ip_has_no_vt_fields(self, geoip_private_ip_result):
        indicator = Indicator(type=IndicatorType.IP, value="172.16.1.101")
        ctx = build_enrichment_context([(indicator, geoip_private_ip_result)])
        assert len(ctx) == 1
        item = ctx[0]
        assert item["source"] == "GeoIP"
        assert item["status"] == "contributed"
        assert item["summary"] == "Private IP"
        assert "vt_malicious" not in item
        assert "vt_total" not in item
        assert "label" not in item

    def test_source_field_formatters_registry_is_virustotal_only(self):
        """A future source (MISP, etc.) does not inherit VT's field shape by default.

        The registry is the single place that opts a source into extra fields.
        """
        from src.llm.prompt_builder import _SOURCE_FIELD_FORMATTERS

        assert list(_SOURCE_FIELD_FORMATTERS.keys()) == ["virustotal"]

    # -----------------------------------------------------------------
    # A clean VT result is evidence: real denominator, never a fabricated 0/0.
    # -----------------------------------------------------------------

    def test_clean_vt_result_keeps_real_denominator(self):
        indicator = Indicator(type=IndicatorType.IP, value="1.2.3.4")
        result = EnrichmentResult(
            source="virustotal",
            status=EnrichmentStatus.CONTRIBUTED,
            data={"malicious_count": 0, "total_engines": 89},
            summary="0/89 vendors flagged",
            failure_reason=None,
            failure_detail=None,
            last_success_at=None,
        )
        ctx = build_enrichment_context([(indicator, result)])
        assert ctx[0]["vt_malicious"] == 0
        assert ctx[0]["vt_total"] == 89

    # -----------------------------------------------------------------
    # Cache age: a short, factual clause alongside the VT count.
    # -----------------------------------------------------------------

    @pytest.mark.parametrize(
        ("seconds", "expected"),
        [
            (30, "30s old"),
            (90, "1m old"),
            (3661, "1h old"),
            (604800, "7d old"),
        ],
    )
    def test_vt_cache_age_clause_scales_to_unit(self, seconds, expected):
        indicator = Indicator(type=IndicatorType.IP, value="1.2.3.4")
        result = EnrichmentResult(
            source="virustotal",
            status=EnrichmentStatus.CONTRIBUTED,
            data={"malicious_count": 0, "total_engines": 89},
            summary="0/89 vendors flagged",
            failure_reason=None,
            failure_detail=None,
            last_success_at=None,
            cached=True,
            cache_age_seconds=seconds,
        )
        ctx = build_enrichment_context([(indicator, result)])
        assert ctx[0]["vt_cache_age"] == expected

    def test_vt_not_cached_has_no_cache_age_field(self, vt_contributed_result):
        indicator = Indicator(type=IndicatorType.IP, value="1.2.3.4")
        ctx = build_enrichment_context([(indicator, vt_contributed_result)])
        assert "vt_cache_age" not in ctx[0]

    # -----------------------------------------------------------------
    # Guarantee that makes verdict_v5.j2's dead "Enrichment source status"
    # ledger scaffold safe to keep unreachable: build_enrichment_context()
    # never returns anything but CONTRIBUTED items. If this test breaks, the
    # scaffold (see the comment at that block in verdict_v5.j2) starts firing
    # for real, not as inert dead code.
    # -----------------------------------------------------------------

    def test_non_contributed_never_returned_across_full_decision_table(
        self, geoip_public_ip_result, geoip_private_ip_result
    ):
        indicator = Indicator(type=IndicatorType.IP, value="1.2.3.4")
        pairs = [
            # VT: contributed with a real count, contributed with no analysis
            # (both sub-cases), not-configured, failing.
            (
                indicator,
                EnrichmentResult(
                    source="virustotal",
                    status=EnrichmentStatus.CONTRIBUTED,
                    data={"malicious_count": 15, "total_engines": 72},
                    summary="15/72",
                    failure_reason=None,
                    failure_detail=None,
                    last_success_at=None,
                ),
            ),
            (
                indicator,
                EnrichmentResult(
                    source="virustotal",
                    status=EnrichmentStatus.CONTRIBUTED,
                    data={"malicious_count": 0, "total_engines": 0, "not_in_database": True},
                    summary="not in db",
                    failure_reason=None,
                    failure_detail=None,
                    last_success_at=None,
                ),
            ),
            (
                indicator,
                EnrichmentResult(
                    source="virustotal",
                    status=EnrichmentStatus.CONTRIBUTED,
                    data={"malicious_count": 0, "total_engines": 0},
                    summary="no stats",
                    failure_reason=None,
                    failure_detail=None,
                    last_success_at=None,
                ),
            ),
            (indicator, EnrichmentResult.not_configured("virustotal")),
            (indicator, EnrichmentResult.failing("virustotal", FailureReason.OTHER, "x")),
            # GeoIP: contributed (public), contributed (private), not-configured, failing.
            (indicator, geoip_public_ip_result),
            (indicator, geoip_private_ip_result),
            (indicator, EnrichmentResult.not_configured("geoip")),
            (indicator, EnrichmentResult.failing("geoip", FailureReason.OTHER, "x")),
        ]

        ctx = build_enrichment_context(pairs)

        # Replicates verdict_v5.j2's `rejectattr("status", "equalto", "contributed")`.
        non_contributed = [item for item in ctx if item["status"] != "contributed"]
        assert non_contributed == []
        assert all(item["status"] == "contributed" for item in ctx)
        assert len(ctx) == 5  # the 5 genuinely CONTRIBUTED pairs above


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
        # NOT_CONFIGURED is filtered out entirely (decision table), so this
        # must exercise a CONTRIBUTED result to reach _source_display() via
        # the real production function.
        indicator = Indicator(type=IndicatorType.IP, value="1.2.3.4")
        result = EnrichmentResult(
            source=source_key,
            status=EnrichmentStatus.CONTRIBUTED,
            data={},
            summary="test summary",
            failure_reason=None,
            failure_detail=None,
            last_success_at=None,
        )
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

    def test_not_configured_never_reaches_prompt(self, minimal_alert, vt_not_configured_result):
        """Decision table: NOT_CONFIGURED is omitted entirely — no ledger, no mention.

        Exercises the real production path (build_enrichment_context ->
        PromptBuilder), not a hand-built dict, so it proves what a real
        verdict prompt actually contains.
        """
        indicator = Indicator(type=IndicatorType.IP, value="1.2.3.4")
        ctx = build_enrichment_context([(indicator, vt_not_configured_result)])
        builder = PromptBuilder()
        prompt = builder.build(alert=minimal_alert, enrichment_context=ctx)
        assert "NOT_CONFIGURED" not in prompt
        assert "No threat intelligence hits for indicators in this alert." in prompt

    def test_geoip_summary_reaches_prompt_without_vt_shape(
        self, minimal_alert, geoip_public_ip_result
    ):
        """Regression test: GeoIP's real summary reaches the model, source-labelled,
        with no fabricated VirusTotal fields (the v0.1.6 defect this fixes)."""
        indicator = Indicator(type=IndicatorType.IP, value="64.89.161.173")
        ctx = build_enrichment_context([(indicator, geoip_public_ip_result)])
        builder = PromptBuilder()
        prompt = builder.build(alert=minimal_alert, enrichment_context=ctx)
        assert "via GeoIP" in prompt
        assert "LU, AS205759 Ghostly Networks LLC" in prompt
        assert "via VirusTotal" not in prompt
        assert "Classification" not in prompt
        assert "No scan data" not in prompt
        assert "0/0" not in prompt

    def test_geoip_private_ip_summary_reaches_prompt(
        self, minimal_alert, geoip_private_ip_result
    ):
        indicator = Indicator(type=IndicatorType.IP, value="172.16.1.101")
        ctx = build_enrichment_context([(indicator, geoip_private_ip_result)])
        builder = PromptBuilder()
        prompt = builder.build(alert=minimal_alert, enrichment_context=ctx)
        assert "via GeoIP" in prompt
        assert "Private IP" in prompt
        assert "via VirusTotal" not in prompt
        assert "0/0" not in prompt

    def test_session63_spamhaus_scenario_no_fabricated_vt_fields(
        self,
        minimal_alert,
        geoip_public_ip_result,
        geoip_private_ip_result,
        vt_not_configured_result,
    ):
        """End-to-end regression for the reported defect (v0.1.6 change brief):

        172.16.1.101 (private) -> 64.89.161.173 (Spamhaus DROP-listed, LU,
        AS205759 Ghostly Networks LLC), no VT key configured. Before the fix,
        both IPs rendered a fabricated "VirusTotal : 0/0 vendors flagged
        malicious" / "Classification : No scan data" block from the GeoIP
        result; the real GeoIP summaries never reached the model.
        """
        pairs = [
            (Indicator(type=IndicatorType.IP, value="172.16.1.101"), geoip_private_ip_result),
            (Indicator(type=IndicatorType.IP, value="64.89.161.173"), vt_not_configured_result),
            (Indicator(type=IndicatorType.IP, value="64.89.161.173"), geoip_public_ip_result),
        ]
        ctx = build_enrichment_context(pairs)
        builder = PromptBuilder()
        prompt = builder.build(alert=minimal_alert, enrichment_context=ctx)

        assert "LU, AS205759 Ghostly Networks LLC" in prompt
        assert "Private IP" in prompt
        assert "No scan data" not in prompt
        assert "0/0 vendors flagged malicious" not in prompt
        assert "NOT_CONFIGURED" not in prompt
        assert "via VirusTotal" not in prompt

    def test_tls_sni_rendered(self, minimal_alert):
        builder = PromptBuilder()
        prompt = builder.build(alert=minimal_alert)
        assert "evil.example.com" in prompt

    def test_correlated_alert_rendered(self, minimal_alert):
        builder = PromptBuilder("verdict_v6")  # v6 flat CORRELATED section
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
        builder = PromptBuilder("verdict_v6")  # v6 flat CORRELATED section
        prompt = builder.build(alert=minimal_alert, correlated_events=[])
        assert "No correlated context events" in prompt

    def test_prompt_version_attribute(self):
        builder = PromptBuilder()
        assert builder.prompt_version == "verdict_v7"

    def test_custom_prompt_version_raises_on_missing_template(self):
        import jinja2
        builder = PromptBuilder(prompt_version="nonexistent_v99")
        with pytest.raises(jinja2.TemplateNotFound):
            builder.build(alert={"alert": {}, "timestamp": "x"})

    def test_vt_cached_result_shows_cache_age_clause(self, minimal_alert, vt_contributed_result):
        vt_contributed_result.cached = True
        vt_contributed_result.cache_age_seconds = 600
        indicator = Indicator(type=IndicatorType.IP, value="1.2.3.4")
        ctx = build_enrichment_context([(indicator, vt_contributed_result)])
        builder = PromptBuilder()
        prompt = builder.build(alert=minimal_alert, enrichment_context=ctx)
        assert "10m old" in prompt

    def test_vt_not_cached_shows_no_cache_clause(self, minimal_alert, vt_contributed_result):
        indicator = Indicator(type=IndicatorType.IP, value="1.2.3.4")
        ctx = build_enrichment_context([(indicator, vt_contributed_result)])
        builder = PromptBuilder()
        prompt = builder.build(alert=minimal_alert, enrichment_context=ctx)
        assert "cached result" not in prompt

    def test_reusable_across_calls(self, minimal_alert):
        builder = PromptBuilder()
        p1 = builder.build(alert=minimal_alert)
        p2 = builder.build(alert=minimal_alert)
        assert p1 == p2


class TestDnsRendering:
    """Regression tests for verdict_v6's DNS query/response fix.

    verdict_v5 (and every earlier version) read the query name only from flat
    dns.rrname, the resolved IP only from flat dns.rdata, and never referenced
    dns.rcode. Real Suricata 8.x EVE nests the query name under
    dns.queries[].rrname (confirmed live on the sensor host, dns.version 3),
    and every EVE dns.version — 2 and 3 alike — nests the resolved IP under
    dns.answers[].rdata, not dns.rdata (confirmed against the eval corpus's
    dns.version 2 records). v5 silently drops the query name on nested-shape
    records and always drops the resolved IP and rcode. These assertions fail
    against verdict_v5 and pass against verdict_v6.
    """

    def test_nested_query_shape_renders_domain(self, minimal_alert):
        """Suricata 8.x EVE dns.version 3: query name nested under dns.queries[]."""
        builder = PromptBuilder(prompt_version="verdict_v6")
        co_dns = {
            "event_type": "dns",
            "dns": {
                "version": 3,
                "type": "query",
                "queries": [{"rrname": "nested-query.example.com", "rrtype": "A"}],
            },
        }
        prompt = builder.build(alert=minimal_alert, correlated_events=[co_dns])
        assert "nested-query.example.com" in prompt

    def test_flat_query_shape_still_renders_domain(self, minimal_alert):
        """dns.version 2 (eval corpus, Suricata pre-8.x): query name flat at dns.rrname."""
        builder = PromptBuilder(prompt_version="verdict_v6")
        co_dns = {
            "event_type": "dns",
            "dns": {
                "version": 2,
                "type": "query",
                "rrname": "flat-query.example.com",
                "rrtype": "A",
            },
        }
        prompt = builder.build(alert=minimal_alert, correlated_events=[co_dns])
        assert "flat-query.example.com" in prompt

    def test_answer_with_records_renders_resolved_ip_and_rcode(self, minimal_alert):
        """dns.answers[] carries the resolved IP; dns.rdata does not exist on answer records."""
        builder = PromptBuilder(prompt_version="verdict_v6")
        co_dns = {
            "event_type": "dns",
            "dns": {
                "version": 2,
                "type": "answer",
                "rrname": "www.hg301d.cfd",
                "rcode": "NOERROR",
                "answers": [
                    {"rrname": "www.hg301d.cfd", "rrtype": "A", "ttl": 5, "rdata": "43.154.67.170"}
                ],
            },
        }
        prompt = builder.build(alert=minimal_alert, correlated_events=[co_dns])
        assert "www.hg301d.cfd" in prompt
        assert "43.154.67.170" in prompt
        assert "NOERROR" in prompt

    def test_nxdomain_answer_renders_rcode(self, minimal_alert):
        """NXDOMAIN carries no answers[]; the rcode itself is the signal and must render."""
        builder = PromptBuilder(prompt_version="verdict_v6")
        co_dns = {
            "event_type": "dns",
            "dns": {
                "version": 2,
                "type": "answer",
                "rrname": "gone.example.com",
                "rcode": "NXDOMAIN",
            },
        }
        prompt = builder.build(alert=minimal_alert, correlated_events=[co_dns])
        assert "gone.example.com" in prompt
        assert "NXDOMAIN" in prompt

# ---------------------------------------------------------------------------
# ADR-025: v6 pin and verdict_v7 flow context
# ---------------------------------------------------------------------------


def _pin_flow() -> tuple[dict, list[dict], list[dict]]:
    """A fixed alert, its whole flow (alert's own row included) and enrichment."""
    base = {
        "flow_id": 777, "src_ip": "10.0.0.5", "src_port": 50123,
        "dest_ip": "203.0.113.10", "dest_port": 80, "proto": "TCP",
    }
    alert = {
        **base, "timestamp": "2026-11-09T10:00:05.000000+0000", "event_type": "alert",
        "app_proto": "http", "tx_id": 1,
        "alert": {"signature_id": 2000001, "signature": "ET MALWARE Test Checkin",
                  "category": "A Network Trojan was Detected", "severity": 1},
        "http": {"hostname": "c2.example.net", "url": "/gate.php", "http_method": "POST",
                 "http_user_agent": "Mozilla/4.0", "status": 200},
        "flow": {"start": "2026-11-09T10:00:00.000000+0000"},
    }
    flow = [
        {**base, "timestamp": "2026-11-09T10:00:00.100000+0000", "event_type": "dns",
         "dest_port": 53, "proto": "UDP",
         "dns": {"version": 3, "type": "request", "tx_id": 0, "id": 4242,
                 "queries": [{"rrname": "c2.example.net", "rrtype": "A"}]}},
        {**base, "timestamp": "2026-11-09T10:00:00.200000+0000", "event_type": "dns",
         "dest_port": 53, "proto": "UDP",
         "dns": {"version": 3, "type": "response", "tx_id": 1, "id": 4242, "rcode": "NOERROR",
                 "queries": [{"rrname": "c2.example.net", "rrtype": "A"}],
                 "answers": [{"rrname": "c2.example.net", "rrtype": "A",
                              "rdata": "203.0.113.10"}]}},
        {**base, "timestamp": "2026-11-09T10:00:01.000000+0000", "event_type": "http",
         "tx_id": 0, "http": {"hostname": "c2.example.net", "url": "/", "http_method": "GET",
                              "http_user_agent": "Mozilla/4.0", "status": 200}},
        dict(alert),
        {**base, "timestamp": "2026-11-09T10:00:05.000100+0000", "event_type": "http",
         "tx_id": 1, "http": {"hostname": "c2.example.net", "url": "/gate.php",
                              "http_method": "POST", "http_user_agent": "Mozilla/4.0",
                              "status": 200}},
        {**base, "timestamp": "2026-11-09T10:00:06.000000+0000", "event_type": "alert",
         "alert": {"signature_id": 2000002, "signature": "ET INFO Co Alert",
                   "category": "Misc activity", "severity": 3}},
        {**base, "timestamp": "2026-11-09T10:00:07.000000+0000", "event_type": "fileinfo",
         "fileinfo": {"filename": "/gate.php", "size": 12}},
        {**base, "timestamp": "2026-11-09T10:00:08.000000+0000", "event_type": "tls",
         "dest_port": 443, "tls": {"sni": "cdn.example.org", "subject": "CN=cdn.example.org"}},
        {**base, "timestamp": "2026-11-09T10:02:00.000000+0000", "event_type": "http",
         "tx_id": 2, "http": {"hostname": "c2.example.net", "url": "/late", "http_method": "GET",
                              "status": 404}},
        {**base, "timestamp": "2026-11-09T10:05:00.000000+0000", "event_type": "flow",
         "flow": {"bytes_toserver": 1000, "bytes_toclient": 2000}},
    ]
    enrichment = [{
        "type": "domain", "indicator": "c2.example.net", "source": "VirusTotal",
        "status": "contributed", "summary": "15/72 vendors flagged malicious",
        "label": "Confirmed malicious — 15/72 vendors", "vt_malicious": 15, "vt_total": 72,
        "cached": False, "cache_age_seconds": None,
    }]
    return alert, flow, enrichment


# Captured from the pre-v7 code path rendering _pin_flow().
_V6_PIN_PROMPT_SHA256 = "945f9bce5f56051246bca3bf2acdd52963626aae789016c5c57b3d859fec01ab"
_V6_TEMPLATE_SHA256 = "03836dff3879d9eb5198bed74cfd6e119d658d253687e0ffc265d8aa1f74513e"


class TestV6Unchanged:
    def test_v6_template_bytes_unchanged(self):
        raw = (_PROMPTS_DIR / "verdict_v6.j2").read_bytes().replace(b"\r\n", b"\n")
        assert hashlib.sha256(raw).hexdigest() == _V6_TEMPLATE_SHA256

    def test_v6_output_unchanged(self):
        alert, flow, enrichment = _pin_flow()
        prompt = PromptBuilder("verdict_v6").build(
            alert=alert, correlated_events=flow, enrichment_context=enrichment,
            src_hostname="ws01.corp",
        )
        assert hashlib.sha256(prompt.encode()).hexdigest() == _V6_PIN_PROMPT_SHA256

    def test_v6_ignores_flow_context(self):
        alert, flow, enrichment = _pin_flow()
        builder = PromptBuilder("verdict_v6")
        assert not builder.uses_flow_context
        plain = builder.build(alert=alert, correlated_events=flow, enrichment_context=enrichment)
        with_ctx = builder.build(
            alert=alert, correlated_events=flow, enrichment_context=enrichment,
            flow_context=build_flow_context(alert, flow, 30),
        )
        assert plain == with_ctx


def _v7(alert: dict, flow: list[dict], **kw) -> str:
    return PromptBuilder("verdict_v7").build(
        alert=alert, flow_context=build_flow_context(alert, flow, 30), **kw
    )


def _section(prompt: str, heading: str) -> str:
    start = prompt.index(f"## {heading}")
    return prompt[start:prompt.index("---", start)]


class TestV7FlowContext:
    def test_two_sections_replace_correlated_context(self):
        alert, flow, _ = _pin_flow()
        prompt = _v7(alert, flow)
        assert "## THIS TRANSACTION" in prompt
        assert "## OTHER ACTIVITY ON THIS FLOW" in prompt
        assert "CORRELATED FLOW CONTEXT" not in prompt

    def test_transaction_section_holds_the_alerts_own_request(self):
        alert, flow, _ = _pin_flow()
        tx = _section(_v7(alert, flow), "THIS TRANSACTION")
        assert 'http: POST c2.example.net/gate.php (200) UA="Mozilla/4.0"' in tx
        assert "GET c2.example.net/ " not in tx

    def test_other_section_lists_siblings_co_alerts_and_other_types(self):
        alert, flow, _ = _pin_flow()
        other = _section(_v7(alert, flow), "OTHER ACTIVITY ON THIS FLOW")
        assert 'http: GET c2.example.net/ (200) UA="Mozilla/4.0"' in other
        assert "CO-ALERT: ET INFO Co Alert (SID 2000002)" in other
        assert "dns: c2.example.net A -> 203.0.113.10 [NOERROR], 2 records" in other
        assert "tls: SNI=cdn.example.org subject=CN=cdn.example.org" in other
        assert "[fileinfo]" in other

    def test_http_line_without_user_agent_has_no_ua_field(self):
        alert, flow, _ = _pin_flow()
        alert["tx_id"] = 99
        no_ua = {**flow[2], "tx_id": 98, "http": {**flow[2]["http"], "url": "/x"}}
        del no_ua["http"]["http_user_agent"]
        other = _section(_v7(alert, [no_ua]), "OTHER ACTIVITY ON THIS FLOW")
        assert "http: GET c2.example.net/x (200)\n" in other

    def test_alert_itself_and_out_of_window_events_absent(self):
        alert, flow, _ = _pin_flow()
        prompt = _v7(alert, flow)
        assert "CO-ALERT: ET MALWARE Test Checkin" not in prompt
        assert "/late" not in prompt
        assert "bytes_toserver=1000" not in prompt  # flow record logged at timeout

    def test_identical_co_alerts_render_with_count(self):
        alert, flow, _ = _pin_flow()
        dup = next(e for e in flow if e.get("alert", {}).get("signature_id") == 2000002)
        prompt = _v7(alert, [*flow, dict(dup), dict(dup)])
        assert (
            "CO-ALERT: ET INFO Co Alert (SID 2000002) | Category: Misc activity"
            " | Severity: 3 (x3)"
        ) in prompt

    def test_no_details_note(self):
        alert, flow, _ = _pin_flow()
        for key in ("tx_id", "http"):
            alert.pop(key)
        tx = _section(_v7(alert, flow), "THIS TRANSACTION")
        assert "The alert carries no transaction details." in tx

    def test_single_transaction_fallback_note(self):
        alert, flow, _ = _pin_flow()
        for key in ("tx_id", "http"):
            alert.pop(key)
        only = [e for e in flow if e.get("tx_id") == 0]
        tx = _section(_v7(alert, only), "THIS TRANSACTION")
        assert "this is the flow's only HTTP transaction" in tx
        assert "GET c2.example.net/ (200)" in tx

    def test_no_record_in_window_note(self):
        alert, flow, _ = _pin_flow()
        flow = [e for e in flow if e.get("tx_id") != 1]
        tx = _section(_v7(alert, flow), "THIS TRANSACTION")
        assert "No transaction record for this alert was logged within the context window." in tx

    def test_no_record_note_for_transaction_protocol(self):
        # A DNS alert whose response record is outside the window: a record could
        # exist, so the wording says none was logged.
        alert = {
            "timestamp": "2026-11-09T10:00:00.000000+0000", "flow_id": 7,
            "event_type": "alert", "app_proto": "dns",
            "alert": {
                "signature_id": 1, "signature": "ET DNS Test", "category": "x", "severity": 2,
            },
            "dns": {"id": 4, "queries": [{"rrname": "a.example.net", "rrtype": "A"}]},
        }
        tx = _section(_v7(alert, []), "THIS TRANSACTION")
        assert "No transaction record for this alert was logged within the context window." in tx
        assert "produces no transaction records" not in tx

    def test_no_transaction_protocol_note(self):
        # Raw TCP, app_proto failed or absent: no transaction record can exist.
        for app_proto in ("failed", None, "smb"):
            alert = {
                "timestamp": "2026-11-09T10:00:00.000000+0000", "flow_id": 7,
                "event_type": "alert", "proto": "TCP",
                "alert": {
                    "signature_id": 1, "signature": "ET TEST", "category": "x", "severity": 2,
                },
            }
            if app_proto is not None:
                alert["app_proto"] = app_proto
            tx = _section(_v7(alert, []), "THIS TRANSACTION")
            assert "This alert's protocol produces no transaction records." in tx
            assert "within the context window" not in tx

    def test_empty_flow_note(self):
        alert, _, _ = _pin_flow()
        assert "No other activity on this flow." in _v7(alert, [])

    def test_names_cap_and_more_count_render(self):
        alert, _, _ = _pin_flow()
        names = [
            {"timestamp": f"2026-11-09T10:00:01.{i:06d}+0000", "event_type": "tls",
             "flow_id": 777, "tls": {"sni": f"n{i:02d}.example.org"}}
            for i in range(23)
        ]
        prompt = _v7(alert, names)
        assert "(3 more names on this flow not shown)" in prompt
        assert "n19.example.org" in prompt
        assert "n20.example.org" not in prompt

    def test_http_per_host_cap_renders_more_count(self):
        alert, _, _ = _pin_flow()
        reqs = [
            {"timestamp": f"2026-11-09T10:00:01.{i:06d}+0000", "event_type": "http",
             "flow_id": 777, "tx_id": 10 + i,
             "http": {"hostname": "c2.example.net", "url": f"/p{i}", "http_method": "GET"}}
            for i in range(8)
        ]
        assert "(3 more HTTP requests to c2.example.net)" in _v7(alert, reqs)

    def test_missing_keys_do_not_crash(self):
        alert = {"timestamp": "2026-11-09T10:00:00+00:00", "event_type": "alert", "alert": {}}
        sparse = [
            {"timestamp": "2026-11-09T10:00:01+00:00", "event_type": "alert"},
            {"timestamp": "2026-11-09T10:00:01+00:00", "event_type": "flow"},
            {"timestamp": "2026-11-09T10:00:01+00:00", "event_type": "http", "http": {}},
            {"timestamp": "2026-11-09T10:00:01+00:00", "event_type": "dns", "dns": {}},
        ]
        assert "## OTHER ACTIVITY ON THIS FLOW" in _v7(alert, sparse)

    def test_output_is_deterministic_whatever_the_input_order(self):
        alert, flow, _ = _pin_flow()
        assert _v7(alert, flow) == _v7(alert, list(reversed(flow)))

    def test_builds_flow_context_when_not_given(self):
        alert, flow, _ = _pin_flow()
        built = PromptBuilder("verdict_v7").build(alert=alert, correlated_events=flow)
        assert built == _v7(alert, flow)

    def test_rule_text_points_at_new_sections(self):
        alert, flow, _ = _pin_flow()
        prompt = _v7(alert, flow)
        assert "co-alerts on the same flow (listed under OTHER ACTIVITY ON THIS FLOW)" in prompt
        assert "visible in THIS TRANSACTION or OTHER ACTIVITY ON THIS FLOW." in prompt

    def test_only_flow_section_and_rule_4_pointers_differ_from_v6(self):
        v6 = (_PROMPTS_DIR / "verdict_v6.j2").read_text(encoding="utf-8").splitlines()
        v7 = (_PROMPTS_DIR / "verdict_v7.j2").read_text(encoding="utf-8").splitlines()
        cut6 = v6.index("## CORRELATED FLOW CONTEXT (same flow_id = same network connection)")
        cut7 = v7.index("## THIS TRANSACTION (the alert's own request and response on this flow)")
        head6, head7 = v6[:cut6], v7[:cut7]
        assert len(head6) == len(head7)
        changed = [i for i, (a, b) in enumerate(zip(head6, head7)) if a != b]
        assert len(changed) == 1  # Rule 4
        restored = head7[changed[0]].replace(
            " (listed under OTHER ACTIVITY ON THIS FLOW)", ""
        ).replace(
            "visible in THIS TRANSACTION or OTHER ACTIVITY ON THIS FLOW.",
            "visible in correlated events.",
        )
        assert restored == head6[changed[0]]
        tail = "Respond with JSON only:"
        assert v6[v6.index(tail):] == v7[v7.index(tail):]
