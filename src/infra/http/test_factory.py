# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Tests for the shared httpx factory."""
from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest
import respx  # noqa: F401 (imported to activate respx mock decorator)

from src.infra.http.factory import _resolve_ca_bundle, create_http_client

# ---------------------------------------------------------------------------
# User-Agent
# ---------------------------------------------------------------------------


@respx.mock
@pytest.mark.asyncio
async def test_user_agent_header_set() -> None:
    route = respx.get("https://example.com/").mock(return_value=httpx.Response(200))
    async with create_http_client(timeout=5.0, purpose="test") as client:
        await client.get("https://example.com/")
    assert route.called
    sent_ua = route.calls[0].request.headers["user-agent"]
    assert "Verdix/" in sent_ua
    assert "purpose=test" in sent_ua


@respx.mock
@pytest.mark.asyncio
async def test_user_agent_includes_purpose() -> None:
    route = respx.get("https://example.com/").mock(return_value=httpx.Response(200))
    async with create_http_client(timeout=5.0, purpose="virustotal") as client:
        await client.get("https://example.com/")
    sent_ua = route.calls[0].request.headers["user-agent"]
    assert "purpose=virustotal" in sent_ua


# ---------------------------------------------------------------------------
# CA bundle resolution
# ---------------------------------------------------------------------------


def test_ca_bundle_falls_back_to_system_when_no_env(tmp_path: Path) -> None:
    env = {k: v for k, v in os.environ.items() if k not in ("SSL_CERT_FILE", "VX_CA_BUNDLE_PATH")}
    with patch.dict(os.environ, env, clear=True):
        result = _resolve_ca_bundle()
    assert result is True


def test_ca_bundle_uses_ssl_cert_file_when_exists(tmp_path: Path) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_text("fake-cert")
    with patch.dict(os.environ, {"SSL_CERT_FILE": str(ca)}, clear=False):
        result = _resolve_ca_bundle()
    assert result == str(ca)


def test_ca_bundle_skips_ssl_cert_file_when_missing(tmp_path: Path) -> None:
    sc_ca = tmp_path / "sc-ca.pem"
    sc_ca.write_text("fake-cert")
    nonexistent = str(tmp_path / "does_not_exist.pem")
    with patch.dict(
        os.environ,
        {"SSL_CERT_FILE": nonexistent, "VX_CA_BUNDLE_PATH": str(sc_ca)},
        clear=False,
    ):
        result = _resolve_ca_bundle()
    assert result == str(sc_ca)


def test_ca_bundle_ssl_cert_file_takes_priority_over_sc_ca_path(tmp_path: Path) -> None:
    ssl_ca = tmp_path / "ssl.pem"
    ssl_ca.write_text("ssl-cert")
    sc_ca = tmp_path / "sc.pem"
    sc_ca.write_text("sc-cert")
    with patch.dict(
        os.environ,
        {"SSL_CERT_FILE": str(ssl_ca), "VX_CA_BUNDLE_PATH": str(sc_ca)},
        clear=False,
    ):
        result = _resolve_ca_bundle()
    assert result == str(ssl_ca)


def test_ca_bundle_falls_back_to_system_when_both_paths_missing(tmp_path: Path) -> None:
    env = {k: v for k, v in os.environ.items() if k not in ("SSL_CERT_FILE", "VX_CA_BUNDLE_PATH")}
    env["SSL_CERT_FILE"] = str(tmp_path / "missing1.pem")
    env["VX_CA_BUNDLE_PATH"] = str(tmp_path / "missing2.pem")
    with patch.dict(os.environ, env, clear=True):
        result = _resolve_ca_bundle()
    assert result is True


# ---------------------------------------------------------------------------
# Returns a usable AsyncClient
# ---------------------------------------------------------------------------


def test_proxy_env_vars_are_honoured(monkeypatch: pytest.MonkeyPatch) -> None:
    """create_http_client must not disable trust_env; proxy env vars must reach the transport.

    httpx reads HTTP_PROXY / HTTPS_PROXY when trust_env=True (the default).  If
    the factory ever passes trust_env=False or an explicit proxies={} override,
    this test catches the regression.
    """
    for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.internal:3128")

    client = create_http_client(timeout=5.0, purpose="test")

    # httpx stores proxy transports in _mounts keyed by URLPattern.  A proxy-configured
    # transport wraps httpcore.AsyncHTTPProxy instead of httpcore.AsyncConnectionPool.
    # Checking the pool type is the least-fragile way to verify the env var was honoured
    # without making a real network connection.
    proxy_found = any(
        "Proxy" in type(getattr(transport, "_pool", None)).__name__
        for transport in client._mounts.values()
    )
    assert proxy_found, (
        "HTTPS_PROXY not reflected in transport mounts — "
        "factory may be disabling trust_env or overriding proxy settings"
    )


def test_create_http_client_returns_async_client() -> None:
    client = create_http_client(timeout=30.0, purpose="test")
    assert isinstance(client, httpx.AsyncClient)
    # Clean up without an event loop by calling close synchronously via the internal transport
    # (AsyncClient without a running loop; we just verify the type and don't send requests here)
