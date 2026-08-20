# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Human-readable and JSON report generation for eval results."""
from __future__ import annotations

import json
from pathlib import Path

from eval.corpus.schema import EvalResult, VerdictCategory
from eval.scoring import EvalMetrics

_PASS = "✓"
_FAIL = "✗"
_WARN = "⚠"

_TARGETS = {
    "verdict_accuracy": (0.80, ">=80%"),
    "false_negative_rate": (0.05, "<=5%", True),  # lower is better
    "structured_output_reliability": (0.99, ">=99%"),
}


def _pass_fail(value: float, target: float, lower_is_better: bool = False) -> str:
    if lower_is_better:
        return _PASS if value <= target else _FAIL
    return _PASS if value >= target else _FAIL


def print_report(metrics: EvalMetrics, results: list[EvalResult]) -> None:
    print("\n" + "=" * 60)
    print("VERDIX EVAL HARNESS — RESULTS")
    print("=" * 60)
    print(f"  Total entries evaluated : {metrics.total}")
    print(f"  Errors (LLM/timeout)    : {metrics.errors}")
    print()

    acc_ok = _pass_fail(metrics.verdict_accuracy, 0.80)
    fn_ok = _pass_fail(metrics.false_negative_rate, 0.05, lower_is_better=True)
    so_ok = _pass_fail(metrics.structured_output_reliability, 0.99)

    acc_val = metrics.verdict_accuracy * 100
    fn_val = metrics.false_negative_rate * 100
    lat_val = metrics.latency_p95_ms / 1000
    so_val = metrics.structured_output_reliability * 100
    print("  METRIC                          VALUE    TARGET   STATUS")
    print("  " + "-" * 55)
    print(f"  Verdict accuracy                {acc_val:6.1f}%   >=80%    {acc_ok}")
    print(f"  False-negative rate             {fn_val:6.1f}%   <=5%     {fn_ok}")
    print(f"  Latency p95                  {lat_val:7.1f}s   <=180s")
    print(f"  Structured-output reliability   {so_val:6.1f}%   >=99%    {so_ok}")
    print()

    print("  CONFUSION MATRIX (rows=ground_truth, cols=predicted)")
    cats = [c.value for c in VerdictCategory]
    header = "  {:30s}".format("") + "  ".join(f"{c[:12]:12s}" for c in cats)
    print(header)
    for gt in cats:
        row = f"  {gt:30s}"
        for pred in cats:
            count = metrics.per_category_accuracy.get(gt, {}).get(pred, 0)
            marker = "*" if gt != pred and count > 0 else " "
            row += f"{count:11d}{marker} "
        print(row)
    print()

    # Print errors and FN misses
    fn_misses = [r for r in results if r.error is None and r.false_negative]
    if fn_misses:
        print(f"  {_FAIL} FALSE NEGATIVES ({len(fn_misses)}) — TP alerts called FP:")
        for r in fn_misses:
            print(f"    {r.alert_id}  conf={r.confidence_score:.2f}  {r.reasoning[:80]}")
        print()

    wrong = [r for r in results if r.error is None and not r.correct and not r.false_negative]
    if wrong:
        print(f"  {_WARN} OTHER MISCLASSIFICATIONS ({len(wrong)}):")
        for r in wrong:
            gt_val = r.ground_truth.value
            pred_val = r.predicted.value
            print(f"    {r.alert_id}  gt={gt_val}  pred={pred_val}  conf={r.confidence_score:.2f}")
        print()

    errors = [r for r in results if r.error is not None]
    if errors:
        print(f"  {_FAIL} ERRORS ({len(errors)}):")
        for r in errors:
            print(f"    {r.alert_id}  {r.error[:100]}")
        print()

    print("=" * 60)


def save_json_report(
    metrics: EvalMetrics, results: list[EvalResult], output_path: Path, prompt_version: str
) -> None:
    data = {
        "prompt_version": prompt_version,
        "metrics": {
            "total": metrics.total,
            "errors": metrics.errors,
            "verdict_accuracy": metrics.verdict_accuracy,
            "false_negative_rate": metrics.false_negative_rate,
            "latency_p95_ms": metrics.latency_p95_ms,
            "structured_output_reliability": metrics.structured_output_reliability,
        },
        "per_category_accuracy": metrics.per_category_accuracy,
        "results": [r.model_dump() for r in results],
    }
    output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"\nJSON report saved to: {output_path}")
