# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Unit tests for eval scoring metrics."""
import pytest

from eval.corpus.schema import EvalResult, VerdictCategory
from eval.scoring import compute_metrics


def _make_result(
    alert_id: str,
    ground_truth: VerdictCategory,
    predicted: VerdictCategory,
    latency_ms: float = 1000.0,
    first_attempt_valid: bool = True,
    error: str | None = None,
) -> EvalResult:
    return EvalResult(
        alert_id=alert_id,
        ground_truth=ground_truth,
        predicted=predicted,
        confidence_score=0.8,
        reasoning="test",
        contributing_facts=[],
        latency_ms=latency_ms,
        first_attempt_valid=first_attempt_valid,
        attempts=1,
        error=error,
    )


def test_perfect_accuracy():
    results = [
        _make_result("a-001", VerdictCategory.LIKELY_TP, VerdictCategory.LIKELY_TP),
        _make_result("a-002", VerdictCategory.LIKELY_FP, VerdictCategory.LIKELY_FP),
    ]
    m = compute_metrics(results)
    assert m.verdict_accuracy == 1.0
    assert m.false_negative_rate == 0.0


def test_false_negative_rate():
    results = [
        _make_result("a-001", VerdictCategory.LIKELY_TP, VerdictCategory.LIKELY_FP),  # FN
        _make_result("a-002", VerdictCategory.LIKELY_TP, VerdictCategory.LIKELY_TP),  # correct
    ]
    m = compute_metrics(results)
    assert m.false_negative_rate == 0.5


def test_latency_p95():
    results = [
        _make_result(
            f"a-{i:03d}", VerdictCategory.LIKELY_TP, VerdictCategory.LIKELY_TP,
            latency_ms=float(i * 100),
        )
        for i in range(1, 21)  # 100ms to 2000ms
    ]
    m = compute_metrics(results)
    # p95 of 20 items = index 18 (0-based) = 1900ms
    assert m.latency_p95_ms == pytest.approx(1900.0, abs=10.0)


def test_structured_output_reliability():
    results = [
        _make_result("a-001", VerdictCategory.LIKELY_TP, VerdictCategory.LIKELY_TP,
                     first_attempt_valid=True),
        _make_result("a-002", VerdictCategory.LIKELY_FP, VerdictCategory.LIKELY_FP,
                     first_attempt_valid=False),
    ]
    m = compute_metrics(results)
    assert m.structured_output_reliability == 0.5


def test_errors_excluded_from_accuracy():
    results = [
        _make_result("a-001", VerdictCategory.LIKELY_TP, VerdictCategory.LIKELY_TP),
        _make_result("a-002", VerdictCategory.LIKELY_FP, VerdictCategory.LIKELY_FP,
                     error="timeout"),
    ]
    m = compute_metrics(results)
    assert m.total == 2
    assert m.errors == 1
    assert m.verdict_accuracy == 1.0  # only 1 scorable, correct
