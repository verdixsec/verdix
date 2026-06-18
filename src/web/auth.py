# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Session management and login lockout for the v0.1 static-admin-password auth.

A single 'admin' user is authenticated against SC_ADMIN_PASSWORD.
Failed attempts are tracked per client IP; 5 failures triggers a 60-second lockout.
Session state is stored in a signed cookie via Starlette SessionMiddleware.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import time

from fastapi import Request

_LOCKOUT_SECONDS = 60
_MAX_FAILURES = 5

# {ip: {"failures": int, "locked_until": float (epoch)}}
_lockout: dict[str, dict[str, float | int]] = {}


def session_secret() -> str:
    """Derive a stable session secret from SC_ADMIN_PASSWORD.

    Stable across restarts (sessions survive container restart as long as
    the password env var doesn't change). Uses a fixed salt so an empty
    password still produces a non-trivial secret.
    """
    pw = os.environ.get("VX_ADMIN_PASSWORD", "")
    return hashlib.sha256(f"vx-session-v1:{pw}".encode()).hexdigest()


def verify_password(password: str) -> bool:
    expected = os.environ.get("VX_ADMIN_PASSWORD", "")
    if not expected:
        return False
    return hmac.compare_digest(password.encode(), expected.encode())


def get_session_user(request: Request) -> str | None:
    return request.session.get("user")


def is_authenticated(request: Request) -> bool:
    return bool(request.session.get("user"))


def check_lockout(ip: str) -> float | None:
    """Return locked_until epoch if IP is currently locked out, else None."""
    entry = _lockout.get(ip)
    if not entry:
        return None
    locked_until = float(entry.get("locked_until", 0))
    if locked_until and time.time() < locked_until:
        return locked_until
    return None


def record_failure(ip: str) -> tuple[int, float | None]:
    """Record a failed attempt. Returns (total_failures, locked_until | None)."""
    entry = _lockout.setdefault(ip, {"failures": 0, "locked_until": 0.0})
    if float(entry.get("locked_until", 0)) and time.time() > float(entry["locked_until"]):
        entry["failures"] = 0
        entry["locked_until"] = 0.0
    entry["failures"] = int(entry["failures"]) + 1
    if int(entry["failures"]) >= _MAX_FAILURES:
        locked_until = time.time() + _LOCKOUT_SECONDS
        entry["locked_until"] = locked_until
        return int(entry["failures"]), locked_until
    return int(entry["failures"]), None


def clear_failures(ip: str) -> None:
    _lockout.pop(ip, None)
