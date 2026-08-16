# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Routes for the first-run setup flow: EULA and system health check."""
from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from src.web.app import templates
from src.web.deps import check_license_accepted, get_operational_store, mark_license_accepted
from src.web.health_check import check_blocked_paths, run_health_check

router = APIRouter()


@router.get("/setup/license")
async def get_license(request: Request):
    if await check_license_accepted():
        return RedirectResponse("/setup/health", status_code=303)
    return templates.TemplateResponse(request, "setup_license.html")


@router.post("/setup/license")
async def post_license(
    request: Request,
    accepted: str = Form(...),
):
    if accepted != "true":
        return templates.TemplateResponse(request, "setup_license.html", {"declined": True})
    store = get_operational_store()
    await store.set_config("eula_accepted", "true")
    await store.set_config("eula_accepted_at", datetime.now(UTC).isoformat())

    # Ensure the install UUID exists — created here so it's ready before any feedback
    from src.telemetry.install_id import ensure_install_id
    await ensure_install_id(store)

    mark_license_accepted()
    return RedirectResponse("/setup/health", status_code=303)


@router.get("/setup/health")
async def get_health_check(request: Request):
    """Also serves as the Re-check action (ADR-019 Stage 3) — the page's
    Retry button targets this same GET route, so every load re-probes."""
    status = getattr(request.app.state, "ingestion_status", None)
    result = await run_health_check(status)
    blocked = status is not None and status.blocked_reason is not None
    context: dict = {"health": result.to_dict(), "blocked": blocked}
    if blocked:
        context["blocked_recheck"] = check_blocked_paths()
    return templates.TemplateResponse(request, "setup_health.html", context)
