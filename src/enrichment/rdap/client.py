# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""RDAP domain registration enrichment client.

Queries the appropriate TLD registry's RDAP endpoint (discovered via the IANA
bootstrap registry) for domain registration age and registrar information.

Key behaviours:
  - Domain indicators only; IP, hash, URL return NOT_CONFIGURED.
  - No credentials required — RDAP is a public protocol (RFC 9083).
  - Requires outbound HTTPS to public registries; degrades to FAILING when blocked.
  - Cache TTL 7 days (domain registration age changes slowly).
  - Circuit breaker: 5 consecutive failures → open for 60s cooldown.
  - Timeout: VX_RDAP_TIMEOUT_SECONDS (default 15s).
  - Returns registration age and registrar: "registered 12 days ago via Namecheap"

RDAP response parsing follows RFC 9083. Key fields:
  - events[].eventAction == "registration" → eventDate
  - entities[].roles includes "registrar" → vcardArray name
"""
from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

import structlog

from src.enrichment.models import (
    EnrichmentResult,
    EnrichmentStatus,
    FailureReason,
    Indicator,
    IndicatorType,
)
from src.enrichment.rdap.bootstrap import RDAPBootstrap
from src.infra.circuit_breaker import AsyncCircuitBreaker, CircuitBreakerOpen
from src.infra.http.factory import create_http_client
from src.interfaces.cache import Cache

logger = structlog.get_logger(__name__)

_DEFAULT_TIMEOUT = float(os.environ.get("VX_RDAP_TIMEOUT_SECONDS", "15"))
_CACHE_TTL = 7 * 24 * 3600  # 7 days
_SOURCE = "rdap"


class RDAPClient:
    """ThreatIntelProvider for domain registration age and registrar via RDAP.

    Args:
        cache:          Cache instance (enrichment results stored 7 days).
        timeout:        Per-query HTTP timeout.
        fail_max:       CB opens after this many consecutive failures.
        reset_timeout:  Seconds before CB attempts a probe.
    """

    def __init__(
        self,
        cache: Cache,
        *,
        timeout: float = _DEFAULT_TIMEOUT,
        fail_max: int = 5,
        reset_timeout: int = 60,
    ) -> None:
        self._cache = cache
        self._timeout = timeout
        self._bootstrap = RDAPBootstrap(cache, timeout=10.0)
        self._cb = AsyncCircuitBreaker(
            fail_max=fail_max,
            reset_timeout=float(reset_timeout),
        )

    async def lookup(self, indicator: Indicator) -> EnrichmentResult:
        """Return RDAP registration data for the domain. Never raises."""
        if indicator.type is not IndicatorType.DOMAIN:
            return EnrichmentResult.not_configured(_SOURCE)

        domain = _normalise_domain(indicator.value)
        cache_key = f"rdap:{domain}"

        cached = await self._cache.get(cache_key)
        if cached is not None:
            return _build_result(cached, cached=True, cache_age_seconds=cached.get("_age_s", 0))

        try:
            data = await self._cb.call(self._fetch, domain)
        except CircuitBreakerOpen:
            return EnrichmentResult.failing(
                _SOURCE,
                FailureReason.CIRCUIT_BREAKER_OPEN,
                "Circuit breaker open — RDAP registries temporarily unreachable",
            )
        except _RDAPTimeout as exc:
            return EnrichmentResult.failing(_SOURCE, FailureReason.TIMEOUT, str(exc))
        except _RDAPNetworkError as exc:
            return EnrichmentResult.failing(_SOURCE, FailureReason.NETWORK_ERROR, str(exc))
        except _RDAPNotFound:
            # Domain not found in registry — return as CONTRIBUTED with no data fields.
            result = EnrichmentResult(
                source=_SOURCE,
                status=EnrichmentStatus.CONTRIBUTED,
                data={"not_found": True},
                summary="Domain not found in RDAP",
                failure_reason=None,
                failure_detail=None,
                last_success_at=datetime.now(UTC),
            )
            await self._cache.set(cache_key, {"not_found": True, "_age_s": 0}, _CACHE_TTL)
            return result
        except Exception as exc:
            return EnrichmentResult.failing(_SOURCE, FailureReason.OTHER, str(exc))

        payload = {**data, "_age_s": 0}
        await self._cache.set(cache_key, payload, _CACHE_TTL)
        return _build_result(data, cached=False, cache_age_seconds=None)

    async def _fetch(self, domain: str) -> dict:
        """Fetch RDAP data for the domain. Raises typed exceptions."""
        base_url = await self._bootstrap.get_base_url(domain)
        if not base_url:
            raise _RDAPNetworkError(f"No RDAP registry known for domain: {domain}")

        url = f"{base_url.rstrip('/')}/domain/{domain}"
        try:
            async with create_http_client(self._timeout, "rdap") as client:
                resp = await client.get(url, follow_redirects=True)
        except Exception as exc:
            etype = type(exc).__qualname__
            if "Timeout" in etype:
                raise _RDAPTimeout(f"timeout querying {url}: {exc}") from exc
            raise _RDAPNetworkError(f"network error querying {url}: {exc}") from exc

        if resp.status_code == 404:
            raise _RDAPNotFound(domain)
        resp.raise_for_status()

        try:
            raw = resp.json()
        except Exception as exc:
            raise _RDAPNetworkError(f"malformed RDAP response: {exc}") from exc

        return _parse_rdap(raw)


# ---------------------------------------------------------------------------
# Internal exception types
# ---------------------------------------------------------------------------

class _RDAPTimeout(Exception):
    pass


class _RDAPNetworkError(Exception):
    pass


class _RDAPNotFound(Exception):
    pass


# ---------------------------------------------------------------------------
# RDAP response parsing (RFC 9083)
# ---------------------------------------------------------------------------

def _parse_rdap(raw: dict) -> dict:
    """Extract registration date, expiry, registrar, and age from an RDAP response."""
    registration_date: datetime | None = None
    expiry_date: datetime | None = None
    registrar: str | None = None

    for event in raw.get("events", []):
        action = event.get("eventAction", "")
        try:
            dt = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
        except (KeyError, ValueError):
            continue
        if action == "registration":
            registration_date = dt
        elif action == "expiration":
            expiry_date = dt

    for entity in raw.get("entities", []):
        roles = entity.get("roles", [])
        if "registrar" in roles:
            vcard = entity.get("vcardArray", [])
            registrar = _extract_vcard_name(vcard)

    now = datetime.now(UTC)
    age_days: int | None = None
    expiry_days: int | None = None
    if registration_date is not None:
        age_days = (now - registration_date).days
    if expiry_date is not None:
        expiry_days = (expiry_date - now).days

    return {
        "registration_date": registration_date.isoformat() if registration_date else None,
        "expiry_date": expiry_date.isoformat() if expiry_date else None,
        "registrar": registrar,
        "age_days": age_days,
        "expiry_days": expiry_days,
    }


def _extract_vcard_name(vcard: Any) -> str | None:
    """Extract fn (full name) from a vCard array."""
    if not isinstance(vcard, list) or len(vcard) < 2:
        return None
    properties = vcard[1] if isinstance(vcard[1], list) else []
    for prop in properties:
        if isinstance(prop, list) and len(prop) >= 4 and prop[0] == "fn":
            return str(prop[3])
    return None


def _normalise_domain(domain: str) -> str:
    """Strip to the registrable domain (eTLD+1) for RDAP lookup.

    RDAP registries index registered domains, not subdomains. Querying
    'scxzswx.lovestoblog.com' always returns 404; 'lovestoblog.com' returns
    real registration data. Handles compound TLDs like .co.uk by keeping the
    last 3 labels; falls back to last 2 labels for all standard TLDs.
    """
    domain = domain.lower().strip().rstrip(".")
    if domain.startswith("www."):
        domain = domain[4:]

    parts = domain.split(".")
    if len(parts) <= 2:
        return domain

    # Known compound public suffixes — take last 3 labels.
    _COMPOUND = {
        "co.uk", "co.nz", "co.au", "co.jp", "co.za", "co.ke",
        "com.au", "com.br", "com.mx", "com.ar", "com.tr", "com.sg",
        "net.au", "net.br", "org.uk", "org.au", "me.uk",
    }
    if ".".join(parts[-2:]) in _COMPOUND:
        return ".".join(parts[-3:])

    # Default: last 2 labels (covers .com, .net, .org, .io, .biz, etc.)
    return ".".join(parts[-2:])


def _build_result(
    data: dict,
    *,
    cached: bool,
    cache_age_seconds: int | None,
) -> EnrichmentResult:
    if data.get("not_found"):
        return EnrichmentResult(
            source=_SOURCE,
            status=EnrichmentStatus.CONTRIBUTED,
            data=data,
            summary="Domain not found in RDAP",
            failure_reason=None,
            failure_detail=None,
            last_success_at=datetime.now(UTC),
            cached=cached,
            cache_age_seconds=cache_age_seconds,
        )

    age_days = data.get("age_days")
    expiry_days = data.get("expiry_days")
    registrar = data.get("registrar")

    parts: list[str] = []
    if age_days is not None:
        parts.append(f"registered {age_days} days ago")
    if registrar:
        parts.append(f"via {registrar}")
    if expiry_days is not None and expiry_days <= 90:
        parts.append(f"expires in {expiry_days} days")

    summary = " ".join(parts) if parts else "registration data available"

    return EnrichmentResult(
        source=_SOURCE,
        status=EnrichmentStatus.CONTRIBUTED,
        data=data,
        summary=summary,
        failure_reason=None,
        failure_detail=None,
        last_success_at=datetime.now(UTC),
        cached=cached,
        cache_age_seconds=cache_age_seconds,
    )
