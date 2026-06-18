# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""HTTP client for submitting feedback and deletion requests to the configured endpoint.

All calls are fire-and-forget: failures are logged but never raised to callers.
Uses the shared httpx factory so proxy and CA bundle settings apply automatically.
The endpoint and the shared bearer token are read fresh from the environment on
every call. If no endpoint is set the submission stays local-only (no POST).
"""
from __future__ import annotations

import os
from typing import Any

import structlog

from src.infra.http.factory import create_http_client

logger = structlog.get_logger(__name__)

_TIMEOUT_S = 10.0


def _endpoint() -> str:
    return os.environ.get("VX_FEEDBACK_ENDPOINT", "").strip()


async def submit(payload: dict[str, Any]) -> bool:
    """POST payload to the configured feedback endpoint.

    Returns True if the server accepted the submission (2xx), False otherwise.
    Returns False without sending if no endpoint is configured.
    Never raises — callers are not expected to handle failures.
    """
    endpoint = _endpoint()
    if not endpoint:
        logger.info("feedback endpoint unset; local-only")
        return False

    # Shared public anti-junk token that ships with the app — not a secret, not
    # per-user, not real auth. Sent as a header (never a URL query param) so it
    # cannot leak into request logs.
    headers: dict[str, str] = {}
    token = os.environ.get("VX_FEEDBACK_TOKEN", "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        async with create_http_client(timeout=_TIMEOUT_S, purpose="feedback") as client:
            resp = await client.post(endpoint, json=payload, headers=headers)
            ok = resp.status_code in (200, 201, 202)
            if not ok:
                logger.warning(
                    "feedback_submit_failed",
                    status=resp.status_code,
                    endpoint=endpoint,
                )
            return ok
    except Exception as exc:  # noqa: BLE001
        logger.warning("feedback_submit_error", error=str(exc), endpoint=endpoint)
        return False


def endpoint_configured() -> bool:
    return bool(_endpoint())
