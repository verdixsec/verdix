# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Tests for ReverseDNSIdentityProvider (ADR-012)."""
from __future__ import annotations

import asyncio
import ipaddress
import socket
from datetime import datetime
from unittest.mock import patch

from src.identity.reverse_dns.provider import ReverseDNSIdentityProvider
from src.infra.cache.memory import InMemoryTTLCache
from src.infra.suricata_config.models import SuricataConfig

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

HOME = [ipaddress.IPv4Network("10.0.0.0/8")]
INTERNAL_IP = "10.0.0.50"
EXTERNAL_IP = "185.220.101.45"


def _config(home_net=None) -> SuricataConfig:
    return SuricataConfig(
        home_net=home_net or HOME,
        external_net=[],
        server_groups={},
        port_groups={},
        rule_file_paths=[],
        rule_file_summaries={},
        config_file_paths_read=[],
        read_at=datetime(2026, 5, 9),
        raw_yaml_hash="test",
    )


def _provider(**kwargs) -> tuple[ReverseDNSIdentityProvider, InMemoryTTLCache]:
    cache = InMemoryTTLCache()
    kwargs.setdefault("timeout", 1.0)
    provider = ReverseDNSIdentityProvider(_config(), cache, **kwargs)
    return provider, cache


# ---------------------------------------------------------------------------
# Scope filtering
# ---------------------------------------------------------------------------


async def test_external_ip_returns_none():
    provider, _ = _provider()
    result = await provider.resolve_ip(EXTERNAL_IP)
    assert result is None


async def test_disabled_returns_none_for_internal():
    provider, _ = _provider(enabled=False)
    result = await provider.resolve_ip(INTERNAL_IP)
    assert result is None


# ---------------------------------------------------------------------------
# Successful resolution
# ---------------------------------------------------------------------------


async def test_resolves_internal_ip_to_hostname():
    provider, _ = _provider()
    with patch("socket.gethostbyaddr", return_value=("jdoe-laptop-01", [], [INTERNAL_IP])):
        result = await provider.resolve_ip(INTERNAL_IP)

    assert result is not None
    assert result.hostname == "jdoe-laptop-01"
    assert result.ip == INTERNAL_IP
    assert result.source == "reverse_dns"
    assert result.username is None
    assert result.ou_path is None
    assert result.group_memberships == []


# ---------------------------------------------------------------------------
# Failure modes — graceful degradation
# ---------------------------------------------------------------------------


async def test_nxdomain_returns_hostname_none():
    """socket.herror (NXDOMAIN) → hostname=None, no exception propagated."""
    provider, _ = _provider()
    with patch("socket.gethostbyaddr", side_effect=socket.herror("no PTR")):
        result = await provider.resolve_ip(INTERNAL_IP)

    assert result is not None
    assert result.hostname is None


async def test_timeout_returns_hostname_none():
    """asyncio.TimeoutError → hostname=None, no exception propagated."""
    provider, _ = _provider(timeout=0.001)

    async def _slow(*_args):
        await asyncio.sleep(10)
        return ("host", [], [])

    with patch("asyncio.to_thread", side_effect=_slow):
        result = await provider.resolve_ip(INTERNAL_IP)

    assert result is not None
    assert result.hostname is None


async def test_dns_unreachable_returns_hostname_none():
    """socket.gaierror (DNS server unreachable) → hostname=None, no propagation."""
    provider, _ = _provider()
    with patch("socket.gethostbyaddr", side_effect=socket.gaierror("DNS unreachable")):
        result = await provider.resolve_ip(INTERNAL_IP)

    assert result is not None
    assert result.hostname is None


# ---------------------------------------------------------------------------
# Cache
# ---------------------------------------------------------------------------


async def test_cache_hit_avoids_second_lookup():
    provider, _ = _provider()
    call_count = 0

    def _lookup(_ip):
        nonlocal call_count
        call_count += 1
        return ("cached-host", [], [_ip])

    with patch("socket.gethostbyaddr", side_effect=_lookup):
        r1 = await provider.resolve_ip(INTERNAL_IP)
        r2 = await provider.resolve_ip(INTERNAL_IP)

    assert call_count == 1
    assert r1 is not None and r1.hostname == "cached-host"
    assert r2 is not None and r2.hostname == "cached-host"


async def test_cache_stores_none_hostname_to_avoid_repeated_nxdomain():
    """NXDOMAIN result is cached (as empty string sentinel) to avoid repeated lookups."""
    provider, _ = _provider()
    call_count = 0

    def _lookup(_ip):
        nonlocal call_count
        call_count += 1
        raise socket.herror("no PTR")

    with patch("socket.gethostbyaddr", side_effect=_lookup):
        await provider.resolve_ip(INTERNAL_IP)
        await provider.resolve_ip(INTERNAL_IP)

    assert call_count == 1


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------


async def test_circuit_breaker_opens_after_failures():
    """After fail_max consecutive gaierror failures, the circuit opens and
    subsequent calls return hostname=None immediately without hitting DNS."""
    provider, _ = _provider(fail_max=3, reset_timeout=60)
    call_count = 0

    def _fail(_ip):
        nonlocal call_count
        call_count += 1
        raise socket.gaierror("unreachable")

    # Use different IPs so the cache doesn't deduplicate the failures.
    with patch("socket.gethostbyaddr", side_effect=_fail):
        for i in range(3):
            ip = f"10.0.0.{i + 1}"
            await provider.resolve_ip(ip)

    # Breaker is now open; next call must not reach DNS.
    calls_before = call_count
    with patch("socket.gethostbyaddr", side_effect=_fail):
        result = await provider.resolve_ip("10.0.0.99")

    assert result is not None
    assert result.hostname is None
    assert call_count == calls_before  # no extra DNS call made
