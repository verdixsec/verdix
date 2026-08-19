# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""JSON API routes: /health, /api/health, /api/queue-depth, /api/feedback."""
from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from src.telemetry import client as telemetry_client
from src.telemetry import collector as telemetry_collector
from src.telemetry.install_id import get_install_id
from src.telemetry.models import ACCEPTED_SUBMISSION_TYPES, APP_VERSION, SCHEMA_VERSION
from src.web.auth import is_authenticated
from src.web.deps import get_event_store, get_operational_store
from src.web.health_check import run_health_check

router = APIRouter()

# Rolling average latency used for time-behind estimate (seconds per verdict).
# Falls back to the PRD's p95 CPU estimate until real data is available.
_DEFAULT_LATENCY_S = 150

# Hold references to in-flight fire-and-forget submit tasks so the event loop
# doesn't garbage-collect them mid-request. Tasks discard themselves on done.
_feedback_tasks: set[asyncio.Task] = set()


@router.get("/health")
async def liveness(request: Request):
    """Docker-compose healthcheck endpoint (ADR-019).

    200 when the ingestion pipeline is green; 503 with the reason when it is
    red or blocked (record_blocked() also sets state to "red", so both cases
    are covered by the same check — Stage 3 wires blocked in, this route
    doesn't need to change to handle it). Missing status (e.g. a request
    that never went through main.py's lifespan) reads as healthy rather
    than failing the probe.
    """
    status = getattr(request.app.state, "ingestion_status", None)
    if status is None or status.state != "red":
        return JSONResponse({"status": "ok", "version": APP_VERSION})
    reason = status.blocked_reason or status.last_error or "ingestion pipeline is red"
    return JSONResponse(
        {"status": "red", "reason": reason, "version": APP_VERSION}, status_code=503
    )


@router.get("/api/health")
async def api_health(request: Request):
    """Full system health check — called by the Setup health-check page."""
    status = getattr(request.app.state, "ingestion_status", None)
    result = await run_health_check(status)
    return JSONResponse(result.to_dict())


@router.get("/api/queue-depth")
async def api_queue_depth(request: Request):
    if not is_authenticated(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    status = getattr(request.app.state, "ingestion_status", None)
    if status is not None and status.state == "red":
        reason = status.blocked_reason or status.last_error or "ingestion pipeline is red"
        ingestion = {"state": "red", "reason": reason}
    else:
        ingestion = {"state": "green"}

    store = get_event_store()
    try:
        daily_cap = int(os.environ.get("VX_TRIAGE_DAILY_CAP", "300"))
        analyzed_today = await store.count_analyzed_today()

        # Count alerts not yet analyzed
        pending = await store.query_alerts(status="queued", limit=1000)
        analyzing = await store.query_alerts(status="analyzing", limit=100)
        deferred = await store.query_alerts(status="deferred", limit=1000)
        failed = await store.query_alerts(status="failed", limit=100)

        queued_count = len(pending)
        analyzing_count = len(analyzing)
        deferred_count = len(deferred)
        failed_count = len(failed)

        # Estimate time behind based on default latency
        estimated_seconds = queued_count * _DEFAULT_LATENCY_S
        hours, rem = divmod(estimated_seconds, 3600)
        minutes = rem // 60

        if hours > 0:
            time_behind = f"~{hours}h {minutes}min behind" if minutes else f"~{hours}h behind"
        elif minutes > 0:
            time_behind = f"~{minutes}min behind"
        else:
            time_behind = None

        cap_hit = analyzed_today >= daily_cap

        return JSONResponse({
            "analyzed_today": analyzed_today,
            "daily_cap": daily_cap,
            "cap_hit": cap_hit,
            "queued": queued_count,
            "analyzing": analyzing_count,
            "deferred": deferred_count,
            "failed": failed_count,
            "time_behind": time_behind,
            "ingestion": ingestion,
        })
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.get("/api/feedback-context")
async def api_feedback_context(request: Request):
    """Return context data for the feedback modal pre-fill."""
    if not is_authenticated(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    op_store = get_operational_store()
    ctx = await telemetry_collector.collect_context(op_store)
    metrics = await telemetry_collector.collect_metrics()

    endpoint_note = ""
    if not telemetry_client.endpoint_configured():
        endpoint_note = (
            "VX_FEEDBACK_ENDPOINT is not set — feedback will be logged locally only."
        )

    return JSONResponse({
        "model": ctx.model,
        "enrichment_sources": ctx.enrichment_sources,
        "hardware": {
            "ram_gb": ctx.hardware.ram_gb if ctx.hardware else None,
            "cpu_cores": ctx.hardware.cpu_cores if ctx.hardware else None,
            "gpu_present": ctx.hardware.gpu_present if ctx.hardware else False,
        },
        "days_since_install": ctx.days_since_install,
        "metrics": {
            "alerts_processed_total": metrics.alerts_processed_total,
            "verdicts_likely_fp": metrics.verdicts_likely_fp,
            "verdicts_suspicious": metrics.verdicts_suspicious,
            "verdicts_likely_tp": metrics.verdicts_likely_tp,
            "agreement_rate": metrics.agreement_rate,
            "latency_p95_ms": metrics.latency_p95_ms,
        },
        "endpoint_note": endpoint_note,
    })


@router.post("/api/feedback")
async def api_feedback(request: Request):
    """Accept a feedback or deletion-request submission and forward it.

    Both submission types share this endpoint so the server stamps install_id
    server-side; the browser never sees the install UUID.
    """
    if not is_authenticated(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid_json"}, status_code=400)

    submission_type = (body.get("submission_type") or "feedback").strip()
    if submission_type not in ACCEPTED_SUBMISSION_TYPES:
        return JSONResponse(
            {"detail": "invalid submission_type"}, status_code=422
        )

    feedback_text = (body.get("feedback_text") or "").strip()
    # Feedback requires free text; a deletion request carries pre-filled text.
    if submission_type == "feedback" and not feedback_text:
        return JSONResponse(
            {"detail": "feedback_text is required"}, status_code=422
        )

    # Stamp server-side fields the browser doesn't supply
    op_store = get_operational_store()
    install_id = await get_install_id(op_store) or "unknown"

    payload = {
        "schema_version": SCHEMA_VERSION,
        "submission_type": submission_type,
        "app_version": APP_VERSION,
        "install_id": install_id,
        "submitted_at": datetime.now(UTC).isoformat(),
        "feedback_text": feedback_text,
    }
    if body.get("context"):
        payload["context"] = body["context"]
    if body.get("metrics"):
        payload["metrics"] = body["metrics"]

    # Fire-and-forget — don't block the response on network latency. Hold a
    # reference until the task finishes so it isn't GC'd mid-flight.
    task = asyncio.create_task(telemetry_client.submit(payload))
    _feedback_tasks.add(task)
    task.add_done_callback(_feedback_tasks.discard)

    return JSONResponse({"ok": True})
