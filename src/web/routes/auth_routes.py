# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Login / logout routes."""
from __future__ import annotations

import time

from fastapi import APIRouter, Form, Request
from fastapi.responses import RedirectResponse

from src.web.app import templates
from src.web.auth import (
    check_lockout,
    clear_failures,
    record_failure,
    verify_password,
)

router = APIRouter()


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@router.get("/login")
async def get_login(request: Request, error: str = ""):
    return templates.TemplateResponse(request, "login.html", {"error": error})


@router.post("/login")
async def post_login(request: Request, password: str = Form(...)):
    ip = _client_ip(request)

    locked_until = check_lockout(ip)
    if locked_until:
        remaining = max(0, int(locked_until - time.time()))
        return templates.TemplateResponse(
            request,
            "login.html",
            {"locked": True, "remaining": remaining},
            status_code=429,
        )

    if not verify_password(password):
        failures, locked_until = record_failure(ip)
        if locked_until:
            remaining = max(0, int(locked_until - time.time()))
            return templates.TemplateResponse(
                request,
                "login.html",
                {"locked": True, "remaining": remaining},
                status_code=429,
            )
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "incorrect_password"},
            status_code=401,
        )

    clear_failures(ip)
    request.session["user"] = "admin"
    return RedirectResponse("/queue", status_code=303)


@router.post("/logout")
async def post_logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@router.get("/logout")
async def get_logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)
