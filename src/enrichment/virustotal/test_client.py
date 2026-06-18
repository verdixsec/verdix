# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Tests for VirusTotalClient using respx mocks and fixture mode."""
from __future__ import annotations

import httpx
import respx

from src.enrichment.models import (
    EnrichmentStatus,
    FailureReason,
    Indicator,
    IndicatorType,
)
from src.enrichment.virustotal.client import VirusTotalClient
from src.infra.cache.memory import InMemoryTTLCache

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_IP = Indicator(type=IndicatorType.IP, value="1.2.3.4")
_DOMAIN = Indicator(type=IndicatorType.DOMAIN, value="evil.example.com")
_HASH = Indicator(type=IndicatorType.HASH, value="abc123")

_VT_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4"
_VT_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/evil.example.com"

_VT_RESPONSE_MALICIOUS = {
    "data": {
        "type": "ip_address",
        "id": "1.2.3.4",
        "attributes": {
            "last_analysis_stats": {
                "malicious": 15,
                "suspicious": 2,
                "harmless": 60,
                "undetected": 10,
                "timeout": 0,
            },
            "reputation": -42,
        },
    }
}

_VT_RESPONSE_CLEAN = {
    "data": {
        "type": "ip_address",
        "id": "10.0.0.1",
        "attributes": {
            "last_analysis_stats": {
                "malicious": 0,
                "suspicious": 0,
                "harmless": 87,
                "undetected": 0,
                "timeout": 0,
            },
            "reputation": 0,
        },
    }
}


def _client(
    *, api_key: str = "test-key", fixture_loader=None
) -> tuple[VirusTotalClient, InMemoryTTLCache]:
    cache = InMemoryTTLCache()
    client = VirusTotalClient(
        cache,
        api_key=api_key,
        timeout=5.0,
        fail_max=3,
        reset_timeout=60,
        fixture_loader=fixture_loader,
    )
    return client, cache


# ---------------------------------------------------------------------------
# NOT_CONFIGURED cases
# ---------------------------------------------------------------------------

async def test_no_api_key_returns_not_configured() -> None:
    cache = InMemoryTTLCache()
    client = VirusTotalClient(cache, api_key="")
    result = await client.lookup(_IP)
    assert result.status == EnrichmentStatus.NOT_CONFIGURED


async def test_unsupported_indicator_type_returns_not_configured() -> None:
    client, _ = _client()
    result = await client.lookup(_HASH)
    assert result.status == EnrichmentStatus.NOT_CONFIGURED


# ---------------------------------------------------------------------------
# Fixture mode
# ---------------------------------------------------------------------------

def _fixture_loader(itype: str, value: str) -> dict | None:
    if itype == "ip" and value == "1.2.3.4":
        return _VT_RESPONSE_MALICIOUS
    return None


async def test_fixture_mode_returns_contributed() -> None:
    client, _ = _client(api_key="", fixture_loader=_fixture_loader)
    result = await client.lookup(_IP)
    assert result.status == EnrichmentStatus.CONTRIBUTED
    assert result.data is not None
    assert result.data["malicious_count"] == 15
    assert result.data["total_engines"] == 87
    # summary = (malicious + suspicious) / total = (15+2)/87 = "17/87"
    assert "17/87" in result.summary


async def test_fixture_mode_not_found_returns_zero_detections() -> None:
    client, _ = _client(api_key="", fixture_loader=_fixture_loader)
    result = await client.lookup(_DOMAIN)  # not in fixtures → None → _not_found
    assert result.status == EnrichmentStatus.CONTRIBUTED
    assert result.data["not_in_database"] is True
    assert result.summary == "Not in VT database"


async def test_fixture_mode_no_http_call_made() -> None:
    """Fixture mode must not make any real HTTP calls."""
    client, _ = _client(api_key="test-key", fixture_loader=_fixture_loader)
    with respx.mock(assert_all_called=False) as mock:
        mock.get(_VT_IP_URL).mock(side_effect=Exception("should not be called"))
        result = await client.lookup(_IP)
    assert result.status == EnrichmentStatus.CONTRIBUTED


# ---------------------------------------------------------------------------
# Live HTTP mode — cache miss → live call → result cached
# ---------------------------------------------------------------------------

async def test_cache_miss_triggers_http_call() -> None:
    client, cache = _client()
    with respx.mock() as mock:
        mock.get(_VT_IP_URL).mock(
            return_value=httpx.Response(200, json=_VT_RESPONSE_MALICIOUS)
        )
        result = await client.lookup(_IP)

    assert result.status == EnrichmentStatus.CONTRIBUTED
    assert result.cached is False
    assert result.data["malicious_count"] == 15


async def test_cache_hit_avoids_http_call() -> None:
    client, _ = _client()
    # Populate cache via a first call.
    with respx.mock() as mock:
        mock.get(_VT_IP_URL).mock(
            return_value=httpx.Response(200, json=_VT_RESPONSE_MALICIOUS)
        )
        await client.lookup(_IP)

    # Second call must not make an HTTP request.
    with respx.mock(assert_all_called=False) as mock:
        mock.get(_VT_IP_URL).mock(side_effect=Exception("should not be called"))
        result = await client.lookup(_IP)

    assert result.status == EnrichmentStatus.CONTRIBUTED
    assert result.cached is True
    assert result.cache_age_seconds is not None


async def test_domain_lookup_hits_correct_endpoint() -> None:
    client, _ = _client()
    domain_response = {
        "data": {
            "type": "domain",
            "id": "evil.example.com",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 5, "suspicious": 0,
                    "harmless": 80, "undetected": 2, "timeout": 0,
                },
                "reputation": -10,
            },
        }
    }
    with respx.mock() as mock:
        mock.get(_VT_DOMAIN_URL).mock(
            return_value=httpx.Response(200, json=domain_response)
        )
        result = await client.lookup(_DOMAIN)

    assert result.status == EnrichmentStatus.CONTRIBUTED
    assert result.data["malicious_count"] == 5


async def test_404_returns_contributed_with_zero_detections() -> None:
    client, _ = _client()
    with respx.mock() as mock:
        mock.get(_VT_IP_URL).mock(return_value=httpx.Response(404))
        result = await client.lookup(_IP)

    assert result.status == EnrichmentStatus.CONTRIBUTED
    assert result.data["not_in_database"] is True
    assert result.summary == "Not in VT database"


async def test_401_returns_failing_auth_failed() -> None:
    client, _ = _client()
    with respx.mock() as mock:
        mock.get(_VT_IP_URL).mock(return_value=httpx.Response(401))
        result = await client.lookup(_IP)
    assert result.status == EnrichmentStatus.FAILING
    assert result.failure_reason == FailureReason.AUTH_FAILED


async def test_429_without_cache_returns_failing_rate_limited() -> None:
    client, _ = _client()
    with respx.mock() as mock:
        mock.get(_VT_IP_URL).mock(return_value=httpx.Response(429))
        result = await client.lookup(_IP)
    assert result.status == EnrichmentStatus.FAILING
    assert result.failure_reason == FailureReason.RATE_LIMITED


async def test_malformed_response_returns_failing() -> None:
    client, _ = _client()
    with respx.mock() as mock:
        mock.get(_VT_IP_URL).mock(return_value=httpx.Response(200, json={"bad": "data"}))
        result = await client.lookup(_IP)
    assert result.status == EnrichmentStatus.FAILING
    assert result.failure_reason == FailureReason.MALFORMED_RESPONSE


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------

async def test_circuit_breaker_opens_after_failures() -> None:
    """After fail_max transport errors, subsequent calls return FAILING immediately."""
    client, _ = _client()
    # Trigger fail_max network errors using unique IPs to avoid cache dedup.
    for i in range(3):
        ind = Indicator(type=IndicatorType.IP, value=f"10.0.0.{i + 1}")
        url = f"https://www.virustotal.com/api/v3/ip_addresses/10.0.0.{i + 1}"
        with respx.mock() as mock:
            mock.get(url).mock(side_effect=httpx.NetworkError("unreachable"))
            await client.lookup(ind)

    # Circuit should now be open; next call must not hit the network.
    result = await client.lookup(_IP)
    assert result.status == EnrichmentStatus.FAILING
    assert result.failure_reason == FailureReason.CIRCUIT_BREAKER_OPEN


# ---------------------------------------------------------------------------
# Stale cache fallback
# ---------------------------------------------------------------------------

async def test_stale_cache_served_on_rate_limit() -> None:
    """When a 429 occurs, a stale cached result is returned as CONTRIBUTED."""
    client, cache = _client()
    # Seed the stale cache entry directly.
    import time
    cache_key = f"vt:{_IP.cache_key_suffix}"
    stale_entry = {"response": _VT_RESPONSE_MALICIOUS, "_fetched_at": time.time() - 7200}
    await cache.set(f"{cache_key}:stale", stale_entry, ttl_seconds=3600 * 24 * 7)

    with respx.mock() as mock:
        mock.get(_VT_IP_URL).mock(return_value=httpx.Response(429))
        result = await client.lookup(_IP)

    assert result.status == EnrichmentStatus.CONTRIBUTED
    assert result.cached is True
    assert result.cache_age_seconds >= 7000
