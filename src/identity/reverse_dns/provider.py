# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""ReverseDNSIdentityProvider — v0.1 concrete implementation of IdentityProvider.

Resolves internal IPs to hostnames via reverse DNS (PTR records).
External IPs are out of scope; RDAP and MaxMind provide better signal there.

Key behaviours (ADR-012):
  - Internal IPs only (HOME_NET membership via SuricataConfig.membership_for_ip)
  - When VX_DNS_SERVER is set: uses dnspython with that explicit resolver.
  - When VX_DNS_SERVER is unset: uses stdlib socket.gethostbyaddr() (OS resolver).
  - Lookup runs in asyncio.to_thread(), wrapped in asyncio.wait_for()
  - Cache: Cache interface, key 'revdns:{ip}', configurable TTL (default 1h)
  - Circuit breaker: AsyncCircuitBreaker, opens after 5 consecutive connectivity
    failures, 60s cooldown
  - NXDOMAIN / no PTR record is NOT a CB failure — lookup succeeded, no record
  - Connectivity failures (timeout, server unreachable) ARE CB failures
  - VX_REVDNS_ENABLED=false disables all lookups (returns None immediately)
  - Never raises to caller; degraded result is IdentityFacts(hostname=None)
"""
from __future__ import annotations

import asyncio
import os
import socket
from datetime import UTC, datetime

import structlog

from src.identity.models import IdentityFacts
from src.infra.circuit_breaker import AsyncCircuitBreaker, CircuitBreakerOpen
from src.infra.suricata_config.models import SuricataConfig
from src.interfaces.cache import Cache

logger = structlog.get_logger(__name__)

_DEFAULT_TIMEOUT = float(os.environ.get("VX_REVDNS_TIMEOUT_SECONDS", "2"))
_DEFAULT_TTL = int(os.environ.get("VX_REVDNS_CACHE_TTL_SECONDS", "3600"))
_ENABLED = os.environ.get("VX_REVDNS_ENABLED", "true").lower() not in ("false", "0", "no")
_DNS_SERVER = os.environ.get("VX_DNS_SERVER")  # explicit resolver IP; uses OS resolver when unset


class ReverseDNSIdentityProvider:
    """Hostname-only IdentityProvider backed by stdlib reverse DNS.

    Args:
        config:         Parsed SuricataConfig — used for HOME_NET membership check.
        cache:          Cache instance for deduplication within shifts.
        timeout:        Per-lookup timeout in seconds (VX_REVDNS_TIMEOUT_SECONDS).
        cache_ttl:      Cache TTL in seconds (VX_REVDNS_CACHE_TTL_SECONDS).
        enabled:        When False all lookups are skipped (VX_REVDNS_ENABLED).
        fail_max:       CB opens after this many consecutive connectivity failures.
        reset_timeout:  Seconds before CB attempts a probe request.
    """

    def __init__(
        self,
        config: SuricataConfig,
        cache: Cache,
        *,
        timeout: float = _DEFAULT_TIMEOUT,
        cache_ttl: int = _DEFAULT_TTL,
        enabled: bool = _ENABLED,
        dns_server: str | None = _DNS_SERVER,
        fail_max: int = 5,
        reset_timeout: int = 60,
    ) -> None:
        self._config = config
        self._cache = cache
        self._timeout = timeout
        self._cache_ttl = cache_ttl
        self._enabled = enabled
        self._dns_server = dns_server
        self._cb = AsyncCircuitBreaker(
            fail_max=fail_max,
            reset_timeout=float(reset_timeout),
        )

    async def resolve_ip(self, ip: str) -> IdentityFacts | None:
        """Resolve an IP to IdentityFacts, or None if out of scope.

        Returns:
            None  — external IP (not HOME_NET) or SC_REVDNS_ENABLED=false.
            IdentityFacts(hostname=None)  — lookup failed or circuit open.
            IdentityFacts(hostname=str)   — successful PTR resolution.
        """
        if not self._enabled:
            return None

        memberships = self._config.membership_for_ip(ip)
        if "HOME_NET" not in memberships:
            return None  # ledger: "not applicable"

        cached = await self._cache.get(f"revdns:{ip}")
        if cached is not None:
            return IdentityFacts(
                ip=ip,
                hostname=cached if cached != "" else None,
                username=None,
                ou_path=None,
                group_memberships=[],
                source="reverse_dns",
                queried_at=datetime.now(UTC),
            )

        hostname = await self._do_lookup(ip)
        # Cache "" as a sentinel for "attempted but no PTR record" to avoid
        # repeated NXDOMAIN lookups within the TTL window.
        await self._cache.set(f"revdns:{ip}", hostname or "", self._cache_ttl)

        return IdentityFacts(
            ip=ip,
            hostname=hostname,
            username=None,
            ou_path=None,
            group_memberships=[],
            source="reverse_dns",
            queried_at=datetime.now(UTC),
        )

    async def _do_lookup(self, ip: str) -> str | None:
        """Perform the PTR lookup with CB and timeout. Never raises."""
        try:
            hostname = await self._cb.call(self._lookup_internal, ip)
            if hostname is not None:
                logger.info("revdns_resolved", ip=ip, hostname=hostname)
            else:
                logger.info("revdns_no_ptr_record", ip=ip)
            return hostname
        except CircuitBreakerOpen:
            logger.warning("revdns_circuit_open", ip=ip)
            return None
        except (TimeoutError, socket.gaierror, OSError) as exc:
            logger.warning("revdns_lookup_failed", ip=ip, error=str(exc))
            return None
        except Exception as exc:
            logger.warning("revdns_lookup_error", ip=ip, error=type(exc).__name__, detail=str(exc))
            return None

    async def _lookup_internal(self, ip: str) -> str | None:
        """Actual PTR lookup; raises on connectivity failure so the CB can count it."""
        if self._dns_server:
            return await asyncio.wait_for(
                asyncio.to_thread(_dnspython_lookup, ip, self._dns_server),
                timeout=self._timeout,
            )
        try:
            hostname, _aliases, _addresses = await asyncio.wait_for(
                asyncio.to_thread(socket.gethostbyaddr, ip),
                timeout=self._timeout,
            )
            return hostname
        except socket.herror:
            # No PTR record (NXDOMAIN) — not a connectivity failure; don't trip CB.
            return None
        # socket.gaierror and asyncio.TimeoutError propagate → CB counts as failure.


def _dnspython_lookup(ip: str, dns_server: str) -> str | None:
    """PTR lookup via dnspython using an explicit resolver address.

    NXDOMAIN / NoAnswer → returns None (not a connectivity failure).
    All other exceptions propagate so the circuit breaker can count them.
    """
    import dns.exception
    import dns.resolver
    import dns.reversename

    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [dns_server]
    try:
        rev = dns.reversename.from_address(ip)
        answers = resolver.resolve(rev, "PTR")
        return str(answers[0]).rstrip(".")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return None
    # dns.exception.Timeout, dns.resolver.NoNameservers, etc. propagate → CB failure.
