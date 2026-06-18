# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Tests for RDAPClient and RDAPBootstrap using respx mocks."""
from __future__ import annotations

import asyncio

import httpx
import respx

from src.enrichment.models import (
    EnrichmentStatus,
    FailureReason,
    Indicator,
    IndicatorType,
)
from src.enrichment.rdap.bootstrap import RDAPBootstrap
from src.enrichment.rdap.client import RDAPClient
from src.infra.cache.memory import InMemoryTTLCache

_DOMAIN = Indicator(type=IndicatorType.DOMAIN, value="evil.example.com")
_IP = Indicator(type=IndicatorType.IP, value="1.2.3.4")
_RDAP_BASE = "https://rdap.verisign.com/com/v1/"
# evil.example.com normalises to example.com (eTLD+1 stripping) before the RDAP query.
_RDAP_URL = "https://rdap.verisign.com/com/v1/domain/example.com"
_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"

_BOOTSTRAP_RESPONSE = {
    "version": "1.0",
    "services": [
        [["com", "net"], ["https://rdap.verisign.com/com/v1/"]]
    ]
}

_RDAP_RESPONSE = {
    "objectClassName": "domain",
    "ldhName": "example.com",
    "events": [
        {"eventAction": "registration", "eventDate": "2010-03-15T00:00:00Z"},
        {"eventAction": "expiration", "eventDate": "2026-03-15T00:00:00Z"},
    ],
    "entities": [
        {
            "roles": ["registrar"],
            "vcardArray": [
                "vcard",
                [
                    ["version", {}, "text", "4.0"],
                    ["fn", {}, "text", "GoDaddy"],
                ]
            ]
        }
    ]
}


def _client() -> tuple[RDAPClient, InMemoryTTLCache]:
    cache = InMemoryTTLCache()
    client = RDAPClient(cache, timeout=5.0, fail_max=3, reset_timeout=60)
    return client, cache


# ---------------------------------------------------------------------------
# NOT_CONFIGURED cases
# ---------------------------------------------------------------------------

async def test_ip_indicator_returns_not_configured() -> None:
    client, _ = _client()
    result = await client.lookup(_IP)
    assert result.status == EnrichmentStatus.NOT_CONFIGURED


# ---------------------------------------------------------------------------
# Successful lookup
# ---------------------------------------------------------------------------

async def test_domain_lookup_returns_contributed() -> None:
    client, _ = _client()
    with respx.mock() as mock:
        mock.get(_BOOTSTRAP_URL).mock(return_value=httpx.Response(200, json=_BOOTSTRAP_RESPONSE))
        mock.get(_RDAP_URL).mock(return_value=httpx.Response(200, json=_RDAP_RESPONSE))
        result = await client.lookup(_DOMAIN)

    assert result.status == EnrichmentStatus.CONTRIBUTED
    assert result.data["registrar"] == "GoDaddy"
    assert result.data["age_days"] is not None
    assert result.data["age_days"] > 0
    assert "GoDaddy" in result.summary
    assert "days ago" in result.summary


async def test_domain_normalises_www_prefix() -> None:
    """www.example.com normalises to example.com for the RDAP query."""
    client, _ = _client()
    www_domain = Indicator(type=IndicatorType.DOMAIN, value="www.example.com")
    with respx.mock() as mock:
        mock.get(_BOOTSTRAP_URL).mock(return_value=httpx.Response(200, json=_BOOTSTRAP_RESPONSE))
        mock.get(_RDAP_URL).mock(return_value=httpx.Response(200, json=_RDAP_RESPONSE))
        result = await client.lookup(www_domain)
    assert result.status == EnrichmentStatus.CONTRIBUTED


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------

async def test_cache_hit_avoids_second_rdap_call() -> None:
    client, _ = _client()
    with respx.mock() as mock:
        mock.get(_BOOTSTRAP_URL).mock(return_value=httpx.Response(200, json=_BOOTSTRAP_RESPONSE))
        mock.get(_RDAP_URL).mock(return_value=httpx.Response(200, json=_RDAP_RESPONSE))
        r1 = await client.lookup(_DOMAIN)
    assert r1.status == EnrichmentStatus.CONTRIBUTED

    # Second call — RDAP registry must NOT be called again.
    with respx.mock(assert_all_called=False) as mock:
        mock.get(_RDAP_URL).mock(side_effect=Exception("should not be called"))
        result = await client.lookup(_DOMAIN)

    assert result.status == EnrichmentStatus.CONTRIBUTED
    assert result.cached is True


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------

async def test_404_returns_contributed_not_found() -> None:
    client, _ = _client()
    with respx.mock() as mock:
        mock.get(_BOOTSTRAP_URL).mock(return_value=httpx.Response(200, json=_BOOTSTRAP_RESPONSE))
        mock.get(_RDAP_URL).mock(return_value=httpx.Response(404))
        result = await client.lookup(_DOMAIN)
    assert result.status == EnrichmentStatus.CONTRIBUTED
    assert result.data.get("not_found") is True


async def test_network_error_returns_failing() -> None:
    client, _ = _client()
    with respx.mock() as mock:
        mock.get(_BOOTSTRAP_URL).mock(return_value=httpx.Response(200, json=_BOOTSTRAP_RESPONSE))
        mock.get(_RDAP_URL).mock(side_effect=httpx.NetworkError("unreachable"))
        result = await client.lookup(_DOMAIN)
    assert result.status == EnrichmentStatus.FAILING
    assert result.failure_reason == FailureReason.NETWORK_ERROR


async def test_circuit_breaker_opens_after_failures() -> None:
    client, _ = _client()
    # Trigger fail_max errors using different domains to bypass cache.
    # Bootstrap is cached in-process after the first call, so only mock it once.
    fail_domains = ["fail1.com", "fail2.com", "fail3.com"]
    for i, domain_str in enumerate(fail_domains):
        ind = Indicator(type=IndicatorType.DOMAIN, value=domain_str)
        url = f"https://rdap.verisign.com/com/v1/domain/{domain_str}"
        with respx.mock(assert_all_called=False) as mock:
            mock.get(_BOOTSTRAP_URL).mock(
                return_value=httpx.Response(200, json=_BOOTSTRAP_RESPONSE)
            )
            mock.get(url).mock(side_effect=httpx.NetworkError("unreachable"))
            await client.lookup(ind)

    result = await client.lookup(_DOMAIN)
    assert result.status == EnrichmentStatus.FAILING
    assert result.failure_reason == FailureReason.CIRCUIT_BREAKER_OPEN


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

async def test_bootstrap_uses_fallback_on_download_failure() -> None:
    """If the IANA bootstrap download fails, fallback TLD map is used."""
    cache = InMemoryTTLCache()
    bootstrap = RDAPBootstrap(cache)
    with respx.mock() as mock:
        mock.get("https://data.iana.org/rdap/dns.json").mock(
            side_effect=httpx.NetworkError("offline")
        )
        url = await bootstrap.get_base_url("example.com")
    # Fallback should cover .com
    assert url is not None
    assert "verisign" in url


async def test_bootstrap_cached_avoids_redownload() -> None:
    cache = InMemoryTTLCache()
    bootstrap = RDAPBootstrap(cache)
    with respx.mock() as mock:
        mock.get(_BOOTSTRAP_URL).mock(return_value=httpx.Response(200, json=_BOOTSTRAP_RESPONSE))
        url1 = await bootstrap.get_base_url("example.com")

    # Second call — no HTTP needed (in-process cache).
    with respx.mock(assert_all_called=False) as mock:
        mock.get(_BOOTSTRAP_URL).mock(side_effect=Exception("should not download"))
        url2 = await bootstrap.get_base_url("example.net")

    assert url1 == url2  # both point to verisign


async def test_unknown_tld_returns_none() -> None:
    cache = InMemoryTTLCache()
    bootstrap = RDAPBootstrap(cache)
    bootstrap._tld_map = {"com": "https://rdap.verisign.com/com/v1/"}
    url = await bootstrap.get_base_url("example.xyz")
    assert url is None


async def test_bootstrap_concurrent_lookups_download_once() -> None:
    """Concurrent domain lookups on the same alert must trigger only one download."""
    cache = InMemoryTTLCache()
    bootstrap = RDAPBootstrap(cache)
    download_count = 0

    original_download = bootstrap._download

    async def counting_download() -> dict:
        nonlocal download_count
        download_count += 1
        return await original_download()

    bootstrap._download = counting_download  # type: ignore[method-assign]

    with respx.mock() as mock:
        mock.get(_BOOTSTRAP_URL).mock(return_value=httpx.Response(200, json=_BOOTSTRAP_RESPONSE))
        # Simulate 3 parallel domain lookups (as happens during alert enrichment).
        results = await asyncio.gather(
            bootstrap.get_base_url("a.com"),
            bootstrap.get_base_url("b.net"),
            bootstrap.get_base_url("c.com"),
        )

    assert download_count == 1, f"Expected 1 download, got {download_count}"
    assert all(r is not None for r in results)
