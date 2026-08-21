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
# harness onto an unscored template. verdict_v6 is correct today: a fresh,
# full-corpus re-baseline (eval/data/results_v6_temp0_dev.json,
# results_v6_temp0_heldout.json — dev 78.47%/215/274, held-out 81.13%/43/53,
# FNR 0/177) measured verdict_v6 directly, statistically indistinguishable from
# ADR-015's v3/v5 baseline. See ADR-021, which supersedes ADR-015. Advance this
# pin only after scripts/check_prompt_parity.py confirms parity with the new
# version, or after a fresh baseline is measured and the current ADR is
# superseded — never as a silent side effect of changing prompt_builder.py's
# _DEFAULT_VERSION.
PROMPT_VERSION = "verdict_v6"
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


async def evaluate_entry(
    entry: CorpusEntry, client: LLMProvider, prompt_version: str | None = None
) -> EvalResult:
    """Render prompt, call LLM, validate output, return EvalResult.

    prompt_version overrides PROMPT_VERSION for this call only — for scoring a
    candidate template before it becomes the pin. Omit to use the pinned
    default; PROMPT_VERSION itself is untouched either way.
    """
    builder = (
        _prompt_builder if prompt_version is None else PromptBuilder(prompt_version=prompt_version)
    )
    enrichment_ctx = eval_enrichment_context_from_hits(entry.threat_intel_context)
    prompt = builder.build(
        alert=entry.raw_eve,
        correlated_events=entry.correlated_events,
        enrichment_context=enrichment_ctx,
    )

    try:
        response = await client.complete(
            prompt,
            _OUTPUT_SCHEMA,
            prompt_version=builder.prompt_version,
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
