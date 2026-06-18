# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Tests for the feedback submission client.

Covers the local-only no-send path (no endpoint configured) and the optional
bearer-token header. HTTP is mocked with respx against the real httpx client
built by the shared factory.
"""
from __future__ import annotations

from unittest.mock import patch

import httpx
import respx

from src.telemetry import client as fb_client


async def test_submit_without_endpoint_does_not_send(monkeypatch):
    monkeypatch.delenv("VX_FEEDBACK_ENDPOINT", raising=False)

    with patch("src.telemetry.client.create_http_client") as mock_factory:
        result = await fb_client.submit({"submission_type": "feedback"})

    assert result is False
    # No endpoint means no client is ever built and nothing leaves the host.
    mock_factory.assert_not_called()


async def test_submit_blank_endpoint_does_not_send(monkeypatch):
    monkeypatch.setenv("VX_FEEDBACK_ENDPOINT", "   ")

    with patch("src.telemetry.client.create_http_client") as mock_factory:
        result = await fb_client.submit({"submission_type": "feedback"})

    assert result is False
    mock_factory.assert_not_called()


@respx.mock
async def test_submit_sends_bearer_token_when_set(monkeypatch):
    monkeypatch.setenv("VX_FEEDBACK_ENDPOINT", "https://verdix.dev/api/feedback")
    monkeypatch.setenv("VX_FEEDBACK_TOKEN", "secret-token")
    route = respx.post("https://verdix.dev/api/feedback").mock(
        return_value=httpx.Response(202)
    )

    result = await fb_client.submit({"submission_type": "feedback"})

    assert result is True
    assert route.called
    assert route.calls.last.request.headers["Authorization"] == "Bearer secret-token"


@respx.mock
async def test_submit_omits_auth_header_without_token(monkeypatch):
    monkeypatch.setenv("VX_FEEDBACK_ENDPOINT", "https://verdix.dev/api/feedback")
    monkeypatch.delenv("VX_FEEDBACK_TOKEN", raising=False)
    route = respx.post("https://verdix.dev/api/feedback").mock(
        return_value=httpx.Response(200)
    )

    result = await fb_client.submit({"submission_type": "deletion_request"})

    assert result is True
    header_names = {k.lower() for k in route.calls.last.request.headers.keys()}
    assert "authorization" not in header_names


@respx.mock
async def test_submit_returns_false_on_server_error(monkeypatch):
    monkeypatch.setenv("VX_FEEDBACK_ENDPOINT", "https://verdix.dev/api/feedback")
    monkeypatch.delenv("VX_FEEDBACK_TOKEN", raising=False)
    respx.post("https://verdix.dev/api/feedback").mock(return_value=httpx.Response(500))

    result = await fb_client.submit({"submission_type": "feedback"})

    assert result is False
