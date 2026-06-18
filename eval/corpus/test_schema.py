# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Unit tests for eval corpus schema models."""
import pytest
from pydantic import ValidationError

from eval.corpus.schema import (
    CorpusEntry,
    EvalResult,
    GroundTruth,
    LLMVerdict,
    VerdictCategory,
)


def test_verdict_category_values():
    assert VerdictCategory.LIKELY_FP == "likely_fp"
    assert VerdictCategory.SUSPICIOUS_INVESTIGATE == "suspicious_investigate"
    assert VerdictCategory.LIKELY_TP == "likely_tp"


def test_llm_verdict_valid():
    v = LLMVerdict(
        verdict_category="likely_tp",
        confidence_score=0.9,
        reasoning="Cobalt Strike beacon over HTTPS.",
        contributing_facts=["Known CS SID", "periodic beacon"],
    )
    assert v.verdict_category == VerdictCategory.LIKELY_TP


def test_llm_verdict_confidence_out_of_range():
    with pytest.raises(ValidationError):
        LLMVerdict(
            verdict_category="likely_tp",
            confidence_score=1.5,
            reasoning="test",
            contributing_facts=[],
        )


def test_eval_result_correct():
    r = EvalResult(
        alert_id="x-001",
        ground_truth=VerdictCategory.LIKELY_TP,
        predicted=VerdictCategory.LIKELY_TP,
        confidence_score=0.9,
        reasoning="",
        contributing_facts=[],
        latency_ms=500,
        first_attempt_valid=True,
        attempts=1,
    )
    assert r.correct is True
    assert r.false_negative is False


def test_eval_result_false_negative():
    r = EvalResult(
        alert_id="x-002",
        ground_truth=VerdictCategory.LIKELY_TP,
        predicted=VerdictCategory.LIKELY_FP,
        confidence_score=0.8,
        reasoning="",
        contributing_facts=[],
        latency_ms=600,
        first_attempt_valid=True,
        attempts=1,
    )
    assert r.correct is False
    assert r.false_negative is True


def test_corpus_entry_coerces_null_correlated():
    entry = CorpusEntry(
        alert_id="rig-001",
        pcap_source="test.pcap",
        sensor_id=1,
        raw_eve={
            "event_type": "alert",
            "alert": {"signature": "test", "signature_id": 1, "severity": 1, "category": "test"},
        },
        correlated_events=None,
        ground_truth=GroundTruth(verdict="likely_tp", reasoning="test"),
    )
    assert entry.correlated_events == []
