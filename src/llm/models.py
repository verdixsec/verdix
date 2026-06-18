# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Data models for LLM responses.

VerdictOutput: Pydantic model for the structured JSON the LLM returns.
LLMResponse:   Dataclass returned by LLMProvider.complete() to callers.

Both are decoupled from the eval harness (eval/corpus/schema.py) so the
production triage pipeline has no dependency on eval code.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field


class VerdictOutput(BaseModel):
    """Structured JSON schema the LLM must return for each alert verdict.

    Used by OllamaClient (and GeminiClient) to validate the raw response
    string before building an LLMResponse. Pydantic validation catches
    missing fields, wrong types, and out-of-range confidence scores.
    """

    verdict_category: str = Field(
        pattern=r"^(likely_fp|suspicious_investigate|likely_tp)$"
    )
    confidence_score: float = Field(ge=0.0, le=1.0)
    reasoning: str
    contributing_facts: list[str] = Field(default_factory=list)


@dataclass
class LLMResponse:
    """Structured result returned by LLMProvider.complete() to callers.

    All fields are populated on success. On failure the provider raises
    an AppError subclass — it never returns a partial LLMResponse.
    """

    verdict_category: str
    """One of: 'likely_fp' | 'suspicious_investigate' | 'likely_tp'."""

    confidence_score: float
    """Probability estimate in [0.0, 1.0]."""

    reasoning: str
    """Plain-English explanation suitable for display in the analyst UI."""

    contributing_facts: list[str]
    """Bullet-point facts the LLM cited as driving the verdict."""

    raw_output: dict[str, Any]
    """The verbatim structured JSON the LLM returned (for 'show reasoning')."""

    latency_ms: int
    """Wall-clock time from request send to response parsed, in milliseconds."""

    model_version: str
    """Identifier of the model that produced this response (e.g. 'gemma4:e4b-it-q8_0')."""

    prompt_version: str
    """Template version tag passed by the caller (e.g. 'verdict_v1')."""

    llm_inputs: dict[str, Any] = field(default_factory=dict)
    """The inputs assembled by PromptBuilder and sent to the LLM.

    Stored in the verdict row so the analyst can inspect the full context
    that produced the verdict ('show reasoning' → 'show inputs').
    """

    first_attempt_valid: bool = True
    """True when the first LLM response parsed without error.

    Used by the eval harness to track structured-output reliability.
    """

    attempts: int = 1
    """Total number of LLM calls made (including retries on parse failure)."""
