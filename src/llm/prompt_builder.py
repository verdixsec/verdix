# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""PromptBuilder — assembles the verdict prompt from all triage context.

Usage (production triage worker):
    builder = PromptBuilder()
    enrichment_ctx = build_enrichment_context([(indicator, result), ...])
    prompt = builder.build(
        alert=alert_dict,
        correlated_events=correlated,
        enrichment_context=enrichment_ctx,
    )
    response = await llm.complete(prompt, OllamaClient.OUTPUT_SCHEMA, prompt_version=builder.prompt_version)

Usage (eval harness):
    builder = PromptBuilder()
    enrichment_ctx = eval_enrichment_context_from_hits(entry.threat_intel_context)
    prompt = builder.build(alert=entry.raw_eve, correlated_events=entry.correlated_events,
                           enrichment_context=enrichment_ctx)
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from src.enrichment.models import EnrichmentResult, EnrichmentStatus, Indicator, IndicatorType

_PROMPTS_DIR = Path(__file__).parent / "prompts"
_DEFAULT_VERSION = "verdict_v5"


def build_enrichment_context(
    results: list[tuple[Indicator, EnrichmentResult]],
) -> list[dict[str, Any]]:
    """Convert (Indicator, EnrichmentResult) pairs to template-friendly dicts.

    The model sees successful lookups only: a source that was never configured
    or that failed contributes no information, so it is dropped from the
    returned list entirely, not shown as a ledger entry. (The UI enrichment
    ledger is unaffected — it is built separately from the raw
    (Indicator, EnrichmentResult) pairs in _build_evidence_chain(), not from
    this function's output.)

    Every dict in the returned list has:
      type      — "ip" | "domain" | "hash" | "url"
      indicator — the indicator value
      source    — "VirusTotal" | "GeoIP" | "RDAP" etc.
      status    — "contributed" (the only status that ever reaches this list)
      summary   — one-line summary from EnrichmentResult.summary
      cached    — bool
      cache_age_seconds — int | None

    Additional fields are source-specific and added by an explicit per-source
    formatter (see _SOURCE_FIELD_FORMATTERS) — a source with no formatter gets
    no extra fields and renders from `summary` alone. This is deliberate: a
    newly added source (MISP, etc.) does not inherit VirusTotal's field shape
    by default. Only "virustotal" currently has one, adding:
      vt_malicious — int, real vendor count
      vt_total     — int, real engine count queried (0 means no analysis, see below)
      label        — human-readable verdict, present only when vt_total > 0
      vt_no_analysis_text — str, present only when vt_total == 0 — VT answered
                     but has no analysis to report (not-in-database or an
                     empty scan-stats payload). Never render vt_malicious/
                     vt_total as a count in this case — "0/0" reads as
                     engines-consulted-and-clean, which is false.
      vt_cache_age — str | absent — short clause, only when cached is True

    NOTE for maintainers: the non-CONTRIBUTED filter below is why
    verdict_v5.j2's "Enrichment source status" ledger block is intentionally
    unreachable — see the comment at that block for the byte-parity reason
    it is kept anyway. If you change this filter, that comment goes stale.
    """
    context = []
    for indicator, result in results:
        if result.status is not EnrichmentStatus.CONTRIBUTED:
            continue

        item: dict[str, Any] = {
            "type": indicator.type.value,
            "indicator": indicator.value,
            "source": _source_display(result.source),
            "status": result.status.value,
            "summary": result.summary,
            "cached": result.cached,
            "cache_age_seconds": result.cache_age_seconds,
        }

        formatter = _SOURCE_FIELD_FORMATTERS.get(result.source.lower())
        if formatter is not None:
            item.update(formatter(result))

        context.append(item)
    return context


def eval_enrichment_context_from_hits(
    threat_intel_context: list[Any],
) -> list[dict[str, Any]]:
    """Convert eval-corpus ThreatIntelHit objects to the standard enrichment_context format.

    Allows the eval harness to use the same Jinja template as the production
    triage pipeline without requiring live VT calls or fixture-mode enrichment.

    Args:
        threat_intel_context: list of ThreatIntelHit objects from eval corpus.
    """
    context = []
    for hit in threat_intel_context:
        context.append(
            {
                "type": hit.type,
                "indicator": hit.indicator,
                "source": "VirusTotal",
                "status": "contributed",
                "label": hit.label,
                "vt_malicious": hit.vt_malicious,
                "vt_total": hit.vt_total,
                "summary": f"{hit.vt_malicious}/{hit.vt_total} vendors flagged malicious",
                "cached": False,
                "cache_age_seconds": None,
                "failure_reason": None,
            }
        )
    return context


class PromptBuilder:
    """Renders the verdict prompt template from triage context.

    A single PromptBuilder instance is safe to reuse across many calls —
    the Jinja environment is shared but rendering is stateless.
    """

    def __init__(self, prompt_version: str = _DEFAULT_VERSION) -> None:
        self.prompt_version = prompt_version
        self._env = Environment(
            loader=FileSystemLoader(str(_PROMPTS_DIR)),
            autoescape=select_autoescape(enabled_extensions=()),
        )

    def build(
        self,
        *,
        alert: dict[str, Any],
        correlated_events: list[dict[str, Any]] | None = None,
        enrichment_context: list[dict[str, Any]] | None = None,
        src_hostname: str | None = None,
        dst_hostname: str | None = None,
    ) -> str:
        """Render the verdict prompt and return it as a string.

        Args:
            alert:             Raw EVE alert dict (entry.raw_eve in eval).
            correlated_events: Other EVE events on the same flow_id.
            enrichment_context: Output of build_enrichment_context() or
                                eval_enrichment_context_from_hits(). If None,
                                the template renders "no enrichment available".
            src_hostname:      Resolved hostname for src_ip (reverse DNS); shown
                               as "hostname (IP)" in the prompt when present.
            dst_hostname:      Resolved hostname for dest_ip; same format.
        """
        template = self._env.get_template(f"{self.prompt_version}.j2")
        return template.render(
            alert=alert,
            correlated_events=correlated_events or [],
            enrichment_context=enrichment_context or [],
            src_hostname=src_hostname,
            dst_hostname=dst_hostname,
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _source_display(source: str) -> str:
    _DISPLAY = {
        "virustotal": "VirusTotal",
        "geoip": "GeoIP",
        "rdap": "RDAP",
    }
    return _DISPLAY.get(source.lower(), source)


def _vt_label(malicious: int, total: int) -> str:
    """Classify a genuine count. Only called when total > 0 — see _vt_no_analysis_text
    for the total == 0 case, which is not a count and must not be routed here."""
    if malicious >= 10:
        return f"Confirmed malicious — {malicious}/{total} vendors"
    if malicious > 0:
        return f"Suspicious — {malicious}/{total} vendors"
    return f"Clean — 0/{total} vendors, no detections"


def _vt_no_analysis_text(data: dict) -> str:
    """VT answered but has no analysis to report — total_engines == 0.

    not_in_database (the 404/never-indexed path) and an empty
    last_analysis_stats payload (a 200 response with nothing to report) are
    the same underlying situation from the model's perspective: no engines
    consulted, no verdict to report. Neither may render as an n/m count —
    "0/0 vendors flagged malicious" reads as engines-consulted-and-clean,
    which is the false-exculpatory reading that produced the Spamhaus
    likely_fp misfire. The two cases stay distinguishable in wording only
    because the data lets us name which one occurred.
    """
    if data.get("not_in_database"):
        return "Not in VirusTotal's database — no analysis data returned."
    return "VirusTotal returned no analysis data for this indicator."


def _cache_age_clause(seconds: int) -> str:
    """Short, factual cache-age clause for the prompt, e.g. '3h old', '9d old'."""
    if seconds < 60:
        return f"{seconds}s old"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m old"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h old"
    days = hours // 24
    return f"{days}d old"


def _format_virustotal_fields(result: EnrichmentResult) -> dict[str, Any]:
    """VT-specific prompt fields: real vendor counts, never a fabricated 0/0."""
    data = result.data or {}
    malicious = data.get("malicious_count", 0)
    total = data.get("total_engines", 0)
    fields: dict[str, Any] = {
        "vt_malicious": malicious,
        "vt_total": total,
    }
    if total > 0:
        fields["label"] = _vt_label(malicious, total)
    else:
        fields["vt_no_analysis_text"] = _vt_no_analysis_text(data)
    if result.cached and result.cache_age_seconds is not None:
        fields["vt_cache_age"] = _cache_age_clause(result.cache_age_seconds)
    return fields


# Explicit per-source opt-in for extra template fields. A source with no entry
# here renders from `summary` alone — it does not inherit another source's
# field shape. See build_enrichment_context()'s docstring.
_SOURCE_FIELD_FORMATTERS: dict[str, Any] = {
    "virustotal": _format_virustotal_fields,
}
