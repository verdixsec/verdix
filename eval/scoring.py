# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Compute the four eval metrics from a list of EvalResults."""
from __future__ import annotations

from dataclasses import dataclass

from eval.corpus.schema import EvalResult, VerdictCategory


@dataclass
class EvalMetrics:
    total: int
    errors: int
    verdict_accuracy: float          # % matching ground truth (excluding errors)
    false_negative_rate: float       # % of TP ground-truth called FP by model
    latency_p95_ms: float            # 95th percentile latency in ms
    structured_output_reliability: float  # % valid on first attempt

    # detailed breakdown
    per_category_accuracy: dict[str, dict[str, int]]  # {gt_category: {predicted: count}}


def compute_metrics(results: list[EvalResult]) -> EvalMetrics:
    scorable = [r for r in results if r.error is None]
    errors = len(results) - len(scorable)

    if not scorable:
        return EvalMetrics(
            total=len(results),
            errors=errors,
            verdict_accuracy=0.0,
            false_negative_rate=0.0,
            latency_p95_ms=0.0,
            structured_output_reliability=0.0,
            per_category_accuracy={},
        )

    correct = sum(1 for r in scorable if r.correct)
    verdict_accuracy = correct / len(scorable)

    tp_results = [r for r in scorable if r.ground_truth == VerdictCategory.LIKELY_TP]
    fn_rate = 0.0
    if tp_results:
        fn_count = sum(1 for r in tp_results if r.false_negative)
        fn_rate = fn_count / len(tp_results)

    latencies = sorted(r.latency_ms for r in scorable)
    p95_idx = max(0, int(len(latencies) * 0.95) - 1)
    latency_p95 = latencies[p95_idx] if latencies else 0.0

    first_valid = sum(1 for r in results if r.first_attempt_valid)
    so_reliability = first_valid / len(results)

    # Per-category confusion breakdown
    categories = [c.value for c in VerdictCategory]
    breakdown: dict[str, dict[str, int]] = {
        cat: {pred: 0 for pred in categories} for cat in categories
    }
    for r in scorable:
        breakdown[r.ground_truth.value][r.predicted.value] += 1

    return EvalMetrics(
        total=len(results),
        errors=errors,
        verdict_accuracy=verdict_accuracy,
        false_negative_rate=fn_rate,
        latency_p95_ms=latency_p95,
        structured_output_reliability=so_reliability,
        per_category_accuracy=breakdown,
    )
