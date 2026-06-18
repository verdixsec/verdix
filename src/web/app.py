# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""FastAPI application factory for the Verdix web layer.

Call create_app() to get a configured FastAPI instance. The returned app
has SessionMiddleware and the first-run gate middleware wired in, and all
route modules registered.

Usage (from src/main.py):
    from src.web.app import create_app
    app = create_app()
"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware

from src.web.auth import is_authenticated, session_secret
from src.web.deps import check_license_accepted

TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"

# Module-level templates instance shared by all route modules.
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Paths that bypass every middleware check (liveness probes, static files).
_ALWAYS_OPEN = frozenset({"/health"})

# Paths accessible once license is accepted but before login.
_POST_LICENSE_OPEN = frozenset({"/setup/health", "/login", "/logout", "/api/health"})


def _returns_json_when_unauthed(path: str, method: str) -> bool:
    """True for paths that should 401 rather than redirect when not authenticated."""
    if path.startswith("/api/"):
        return True
    # Disposition POST is a form action but returns JSON on auth failure
    if method == "POST" and path.startswith("/alert/"):
        return True
    return False


class _FirstRunGateMiddleware(BaseHTTPMiddleware):
    """Enforce the EULA → health-check → login → app first-run flow.

    Redirect matrix:
      License not accepted  → /setup/license      (except /setup/license, /api/health, /health)
      License accepted,
        not authenticated   → /login (HTML paths) or 401 (API/POST paths)
      Authenticated trying
        to reach setup/login → /queue
    """

    async def dispatch(self, request: Request, call_next):  # type: ignore[override]
        path = request.url.path

        if path in _ALWAYS_OPEN or path.startswith("/static/"):
            return await call_next(request)

        license_ok = await check_license_accepted()

        if not license_ok:
            if path in ("/setup/license", "/api/health"):
                return await call_next(request)
            return RedirectResponse("/setup/license", status_code=303)

        # License accepted
        authenticated = is_authenticated(request)

        # Already logged in — bounce away from setup/login screens.
        # /setup/health is intentionally excluded: admins can view it any time.
        if authenticated and path in ("/setup/license", "/login"):
            return RedirectResponse("/queue", status_code=303)

        # Protected routes require authentication
        if not authenticated and path not in _POST_LICENSE_OPEN and not path.startswith("/setup/"):
            if _returns_json_when_unauthed(path, request.method):
                return JSONResponse({"error": "unauthorized"}, status_code=401)
            return RedirectResponse("/login", status_code=303)

        return await call_next(request)


def create_app(lifespan=None) -> FastAPI:
    app = FastAPI(title="Verdix", docs_url=None, redoc_url=None, lifespan=lifespan)

    # Add _FirstRunGateMiddleware first (makes it inner in the stack).
    # Add SessionMiddleware last (makes it outermost — runs first on requests),
    # so request.session is populated before the gate middleware executes.
    app.add_middleware(_FirstRunGateMiddleware)
    app.add_middleware(SessionMiddleware, secret_key=session_secret())

    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # Register all route modules
    from src.web.routes.api_routes import router as api_router
    from src.web.routes.alert_routes import router as alert_router
    from src.web.routes.auth_routes import router as auth_router
    from src.web.routes.queue_routes import router as queue_router
    from src.web.routes.setup import router as setup_router

    app.include_router(setup_router)
    app.include_router(auth_router)
    app.include_router(queue_router)
    app.include_router(alert_router)
    app.include_router(api_router)

    @app.get("/")
    async def root():
        return RedirectResponse("/queue", status_code=303)

    return app
