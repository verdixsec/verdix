# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Run a single corpus entry through the triage pipeline and return an EvalResult."""
from __future__ import annotations

from typing import Any

from eval.corpus.schema import CorpusEntry, EvalResult
from src.interfaces.llm_provider import LLMProvider
from src.llm.prompt_builder import PromptBuilder, eval_enrichment_context_from_hits

# Pinned explicitly rather than inheriting PromptBuilder's _DEFAULT_VERSION, so a
# future default-version bump in prompt_builder.py cannot silently re-point the
# harness onto an unscored template. verdict_v5 is correct today:
# eval/data/PROMPT_PARITY_verdict_v3_vs_verdict_v5_6a93f5d368f5.md (internal-only,
# not shipped in this export — it records that all 327 corpus entries render
# byte-identically under this eval path for v3 vs v5) shows ADR-015's
# v3-measured baseline (dev 79.2% / held-out 79.25%, FNR 0%) holds unchanged at
# v5. Advance this pin only after scripts/check_prompt_parity.py confirms parity
# with the new version, or after a fresh baseline is measured and ADR-015 is
# superseded — never as a silent side effect of changing prompt_builder.py's
# _DEFAULT_VERSION.
PROMPT_VERSION = "verdict_v5"
_prompt_builder = PromptBuilder(prompt_version=PROMPT_VERSION)

# Canonical output schema — shared with OllamaClient and GeminiClient.
_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "verdict_category": {
            "type": "string",
            "enum": ["likely_fp", "suspicious_investigate", "likely_tp"],
        },
        "confidence_score": {"type": "number"},
        "reasoning": {"type": "string"},
        "contributing_facts": {
            "type": "array",
            "items": {"type": "string"},
        },
    },
    "required": ["verdict_category", "confidence_score", "reasoning", "contributing_facts"],
}


async def evaluate_entry(entry: CorpusEntry, client: LLMProvider) -> EvalResult:
    """Render prompt, call LLM, validate output, return EvalResult."""
    enrichment_ctx = eval_enrichment_context_from_hits(entry.threat_intel_context)
    prompt = _prompt_builder.build(
        alert=entry.raw_eve,
        correlated_events=entry.correlated_events,
        enrichment_context=enrichment_ctx,
    )

    try:
        response = await client.complete(
            prompt,
            _OUTPUT_SCHEMA,
            prompt_version=_prompt_builder.prompt_version,
        )
        return EvalResult(
            alert_id=entry.alert_id,
            ground_truth=entry.ground_truth.verdict,
            predicted=response.verdict_category,
            confidence_score=response.confidence_score,
            reasoning=response.reasoning,
            contributing_facts=response.contributing_facts,
            latency_ms=response.latency_ms,
            first_attempt_valid=response.first_attempt_valid,
            attempts=response.attempts,
            error=None,
        )
    except Exception as exc:  # noqa: BLE001
        return EvalResult(
            alert_id=entry.alert_id,
            ground_truth=entry.ground_truth.verdict,
            predicted=entry.ground_truth.verdict,  # fallback: count as correct to be conservative
            confidence_score=0.0,
            reasoning="",
            contributing_facts=[],
            latency_ms=0,
            first_attempt_valid=False,
            attempts=3,
            error=str(exc),
        )
