# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Pydantic models for the eval corpus and LLM verdict output."""
from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class VerdictCategory(StrEnum):
    LIKELY_FP = "likely_fp"
    SUSPICIOUS_INVESTIGATE = "suspicious_investigate"
    LIKELY_TP = "likely_tp"


class GroundTruth(BaseModel):
    verdict: VerdictCategory
    reasoning: str


class ThreatIntelHit(BaseModel):
    indicator: str
    type: str  # "ip", "domain", "hash"
    label: str
    vt_malicious: int
    vt_total: int
    source: str = "VirusTotal (eval-time simulation)"


class CorpusEntry(BaseModel):
    alert_id: str
    pcap_source: str
    sensor_id: int
    raw_eve: dict[str, Any]
    correlated_events: list[dict[str, Any]] = Field(default_factory=list)
    threat_intel_context: list[ThreatIntelHit] = Field(default_factory=list)
    ground_truth: GroundTruth
    # Additive provenance/split tags (optional, backward-compatible: corpora that
    # predate these fields still validate with both as None).
    source: str | None = None
    split: str | None = None

    @field_validator("correlated_events", mode="before")
    @classmethod
    def coerce_correlated(cls, v: Any) -> list[dict[str, Any]]:
        if v is None:
            return []
        return list(v)


class LLMVerdict(BaseModel):
    """Structured output schema returned by the LLM."""
    verdict_category: VerdictCategory
    confidence_score: float = Field(ge=0.0, le=1.0)
    reasoning: str
    contributing_facts: list[str] = Field(default_factory=list)


class EvalResult(BaseModel):
    alert_id: str
    ground_truth: VerdictCategory
    predicted: VerdictCategory
    confidence_score: float
    reasoning: str
    contributing_facts: list[str]
    latency_ms: float
    first_attempt_valid: bool
    attempts: int
    error: str | None = None

    @property
    def correct(self) -> bool:
        return self.ground_truth == self.predicted

    @property
    def false_negative(self) -> bool:
        """TP labelled as FP by the model - the safety-critical error."""
        return (
            self.ground_truth == VerdictCategory.LIKELY_TP
            and self.predicted == VerdictCategory.LIKELY_FP
        )
