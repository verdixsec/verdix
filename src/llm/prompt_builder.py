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
_DEFAULT_VERSION = "verdict_v3"


def build_enrichment_context(
    results: list[tuple[Indicator, EnrichmentResult]],
) -> list[dict[str, Any]]:
    """Convert (Indicator, EnrichmentResult) pairs to template-friendly dicts.

    Each dict in the returned list has:
      type          — "ip" | "domain" | "hash" | "url"
      indicator     — the indicator value
      source        — "VirusTotal" | "GeoIP" | "RDAP" etc.
      status        — "contributed" | "failing" | "not_configured"
      label         — human-readable verdict (computed from VT stats)
      vt_malicious  — int (VT contributed results only)
      vt_total      — int (VT contributed results only)
      summary       — one-line summary from EnrichmentResult.summary
      cached        — bool
      cache_age_seconds — int | None
      failure_reason — str | None (failing status only)

    Items with NOT_CONFIGURED status are included in the list — the template
    uses them for the enrichment-source ledger while omitting them from the
    TI-hits section.
    """
    context = []
    for indicator, result in results:
        item: dict[str, Any] = {
            "type": indicator.type.value,
            "indicator": indicator.value,
            "source": _source_display(result.source),
            "status": result.status.value,
            "summary": result.summary,
            "cached": result.cached,
            "cache_age_seconds": result.cache_age_seconds,
            "failure_reason": result.failure_reason.value if result.failure_reason else None,
        }

        if result.status is EnrichmentStatus.CONTRIBUTED and result.data:
            malicious = result.data.get("malicious_count", 0)
            total = result.data.get("total_engines", 0)
            item["vt_malicious"] = malicious
            item["vt_total"] = total
            item["label"] = _vt_label(malicious, total, result.data)

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


def _vt_label(malicious: int, total: int, data: dict) -> str:
    if data.get("not_in_database"):
        return "Not in VirusTotal database"
    if total == 0:
        return "No scan data"
    if malicious >= 10:
        return f"Confirmed malicious — {malicious}/{total} vendors"
    if malicious > 0:
        return f"Suspicious — {malicious}/{total} vendors"
    return f"Clean — 0/{total} vendors, no detections"
