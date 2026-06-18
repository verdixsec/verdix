# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Collects anonymous metrics from the local DB for telemetry/feedback payloads.

Never touches alert content, IP addresses, or analyst reasoning text.
All results are aggregate counts and percentiles.
"""
from __future__ import annotations

import os
import subprocess
from datetime import UTC, datetime

import psutil
from sqlalchemy import text

from src.infra.db.session import get_session
from src.telemetry.models import HardwareContext, SubmissionContext, SubmissionMetrics


async def collect_metrics() -> SubmissionMetrics:
    """Query DB for aggregate verdict and performance metrics."""
    try:
        async with get_session() as session:
            # Total analyzed alerts (all time)
            r = await session.execute(
                text("SELECT COUNT(*) FROM alerts WHERE status = 'analyzed'")
            )
            total_analyzed: int = r.scalar() or 0

            # Verdict distribution (current verdicts only)
            r = await session.execute(
                text(
                    "SELECT verdict_category, COUNT(*) FROM verdicts"
                    " WHERE is_current = 1 GROUP BY verdict_category"
                )
            )
            dist: dict[str, int] = {row[0]: row[1] for row in r.fetchall()}

            # Agreement rate: accepted / total dispositions
            r = await session.execute(
                text(
                    "SELECT"
                    "  SUM(CASE WHEN disposition_action = 'accept' THEN 1 ELSE 0 END),"
                    "  COUNT(*)"
                    " FROM dispositions"
                )
            )
            row = r.fetchone()
            accepted_count = int(row[0] or 0)
            total_disp = int(row[1] or 0)
            agreement_rate = (
                round(accepted_count / total_disp, 3) if total_disp > 0 else None
            )

            # Latency p95 across current non-inherited verdicts
            r = await session.execute(
                text(
                    "SELECT latency_ms FROM verdicts"
                    " WHERE is_current = 1 AND latency_ms > 0"
                    " ORDER BY latency_ms"
                )
            )
            latencies = [int(row[0]) for row in r.fetchall()]
            p95_ms: int | None = None
            if latencies:
                idx = max(0, int(len(latencies) * 0.95) - 1)
                p95_ms = latencies[min(idx, len(latencies) - 1)]

    except Exception:  # noqa: BLE001
        # Degrade gracefully — metrics are optional context, not critical.
        return SubmissionMetrics()

    return SubmissionMetrics(
        alerts_processed_total=total_analyzed,
        verdicts_likely_fp=dist.get("likely_fp", 0),
        verdicts_suspicious=dist.get("suspicious_investigate", 0),
        verdicts_likely_tp=dist.get("likely_tp", 0),
        agreement_rate=agreement_rate,
        latency_p95_ms=p95_ms,
    )


async def collect_context(op_store) -> SubmissionContext:
    """Collect non-sensitive environmental context."""
    model = os.environ.get("VX_OLLAMA_MODEL", "gemma4:e4b-it-q8_0")

    enrichment_sources: list[str] = ["geoip", "rdap"]
    if os.environ.get("VX_VIRUSTOTAL_API_KEY"):
        enrichment_sources.insert(0, "virustotal")

    hardware = _collect_hardware()

    days_since_install: int | None = None
    try:
        installed_at_raw = await op_store.get_config("eula_accepted_at")
        if installed_at_raw:
            installed_at = datetime.fromisoformat(installed_at_raw)
            days_since_install = (datetime.now(UTC) - installed_at).days
    except Exception:  # noqa: BLE001
        pass

    return SubmissionContext(
        model=model,
        enrichment_sources=enrichment_sources,
        hardware=hardware,
        days_since_install=days_since_install,
    )


def _collect_hardware() -> HardwareContext:
    try:
        ram_gb = round(psutil.virtual_memory().total / (1024 ** 3))
    except Exception:  # noqa: BLE001
        ram_gb = None

    cpu_cores = os.cpu_count()

    gpu_present = False
    try:
        result = subprocess.run(
            ["nvidia-smi", "-L"],
            capture_output=True,
            timeout=3,
        )
        gpu_present = result.returncode == 0 and bool(result.stdout.strip())
    except Exception:  # noqa: BLE001
        pass

    return HardwareContext(ram_gb=ram_gb, cpu_cores=cpu_cores, gpu_present=gpu_present)
