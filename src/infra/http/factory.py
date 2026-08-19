# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Shared async HTTP client factory.

All outbound HTTP calls must use create_http_client(). Direct httpx imports
outside this package are banned by ruff (TID251 — see pyproject.toml).
Type-only imports in TYPE_CHECKING blocks are the sole permitted exception.
"""
from __future__ import annotations

import os
from pathlib import Path

import httpx

_VERSION = "0.1.7"
_DEFAULT_CA_BUNDLE_PATH = "/host/certs/ca-bundle.pem"


def create_http_client(timeout: float, purpose: str) -> httpx.AsyncClient:
    """Return a configured async HTTP client for the given purpose.

    Proxy variables (HTTP_PROXY, HTTPS_PROXY, NO_PROXY) are honored automatically
    via httpx's default trust_env=True behaviour.

    CA bundle resolution order:
      1. SSL_CERT_FILE environment variable (standard)
      2. SC_CA_BUNDLE_PATH environment variable (default: /host/certs/ca-bundle.pem)
      3. System CAs (httpx default)
    """
    return httpx.AsyncClient(
        timeout=timeout,
        verify=_resolve_ca_bundle(),
        headers={"User-Agent": f"Verdix/{_VERSION} (purpose={purpose})"},
    )


def _resolve_ca_bundle() -> bool | str:
    """Return a CA bundle path string, or True to use system CAs."""
    ssl_cert_file = os.environ.get("SSL_CERT_FILE")
    if ssl_cert_file:
        p = Path(ssl_cert_file)
        if p.exists():
            return str(p)

    sc_ca_path = os.environ.get("VX_CA_BUNDLE_PATH", _DEFAULT_CA_BUNDLE_PATH)
    p = Path(sc_ca_path)
    if p.exists():
        return str(p)

    return True
