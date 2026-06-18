# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""VirusTotal enrichment client (ADR-005, ADR-007, ADR-008).

Key behaviours:
  - API key from VX_VIRUSTOTAL_API_KEY; if absent → NOT_CONFIGURED, no HTTP call.
  - Cache lookup before live query (key vt:{type}:{value}, TTL 24h).
  - Client-side rate limiter (4 req/min) protects free-tier quota.
  - On 429 or circuit-breaker open: stale cache returned as CONTRIBUTED when
    available, otherwise FAILING with appropriate failure_reason.
  - 404 (indicator not in VT database) → CONTRIBUTED with 0 detections, not FAILING.
  - Handles IP and domain indicators; hash/URL return NOT_CONFIGURED in v0.1.
  - Never raises to caller.

Fixture mode (eval harness):
  Pass a fixture_loader callable to __init__ that accepts (type_str, value) and
  returns a VT API response dict (or None for "not in database"). When set, all
  HTTP calls are bypassed — same parse path as production, deterministic results.
"""
from __future__ import annotations

import os
import time
from collections.abc import Callable
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
from src.infra.circuit_breaker import AsyncCircuitBreaker, CircuitBreakerOpen
from src.infra.http.factory import create_http_client
from src.interfaces.cache import Cache

logger = structlog.get_logger(__name__)

_VT_BASE = "https://www.virustotal.com/api/v3"
_DEFAULT_TIMEOUT = float(os.environ.get("VX_VT_TIMEOUT_SECONDS", "30"))
_CACHE_TTL = int(os.environ.get("VX_VT_CACHE_TTL_SECONDS", str(24 * 3600)))
_SOURCE = "virustotal"
_SUPPORTED = {IndicatorType.IP, IndicatorType.DOMAIN}


class _VTAuthError(Exception):
    pass


class _VTRateLimit(Exception):
    pass


class _VTTransportError(Exception):
    """Wraps httpx network/timeout errors without importing httpx at module level."""
    pass


class VirusTotalClient:
    """ThreatIntelProvider backed by the VirusTotal API v3.

    Args:
        cache:          Cache instance for enrichment result caching.
        api_key:        VT API key; defaults to SC_VIRUSTOTAL_API_KEY env var.
        timeout:        HTTP timeout in seconds.
        fail_max:       CB opens after this many consecutive failures.
        reset_timeout:  Seconds before CB allows a probe request.
        fixture_loader: Optional callable(type_str, value) → dict | None.
                        When set, HTTP calls are bypassed (eval harness mode).
    """

    def __init__(
        self,
        cache: Cache,
        *,
        api_key: str | None = None,
        timeout: float = _DEFAULT_TIMEOUT,
        fail_max: int = 5,
        reset_timeout: int = 60,
        fixture_loader: Callable[[str, str], dict | None] | None = None,
    ) -> None:
        self._api_key = api_key or os.environ.get("VX_VIRUSTOTAL_API_KEY", "")
        self._cache = cache
        self._timeout = timeout
        self._cb = AsyncCircuitBreaker(
            fail_max=fail_max,
            reset_timeout=float(reset_timeout),
        )
        self._fixture_loader = fixture_loader
        self._rate_limiter: Any = None
        if not fixture_loader:
            from src.enrichment.virustotal.rate_limiter import RateLimiter
            self._rate_limiter = RateLimiter()

    async def lookup(self, indicator: Indicator) -> EnrichmentResult:
        """Return an EnrichmentResult for the given indicator. Never raises."""
        if not self._api_key and not self._fixture_loader:
            return EnrichmentResult.not_configured(_SOURCE)

        if indicator.type not in _SUPPORTED:
            return EnrichmentResult.not_configured(_SOURCE)

        cache_key = f"vt:{indicator.cache_key_suffix}"

        # --- Cache lookup ---
        cached_entry = await self._cache.get(cache_key)
        if cached_entry is not None:
            age = int(time.time() - cached_entry.get("_fetched_at", 0.0))
            return _parse_vt_response(
                cached_entry["response"], cached=True, cache_age_seconds=age
            )

        # --- Live query via circuit breaker ---
        try:
            raw = await self._cb.call(self._fetch, indicator)
        except CircuitBreakerOpen:
            return await self._serve_stale_or_failing_async(
                cache_key,
                FailureReason.CIRCUIT_BREAKER_OPEN,
                "Circuit breaker open — VT temporarily unavailable",
            )
        except _VTAuthError as exc:
            return EnrichmentResult.failing(_SOURCE, FailureReason.AUTH_FAILED, str(exc))
        except _VTRateLimit:
            return await self._serve_stale_or_failing_async(
                cache_key,
                FailureReason.RATE_LIMITED,
                "VT rate limit hit",
            )
        except _VTTransportError as exc:
            reason = (
                FailureReason.TIMEOUT if "timeout" in str(exc).lower()
                else FailureReason.NETWORK_ERROR
            )
            return await self._serve_stale_or_failing_async(cache_key, reason, str(exc))
        except Exception as exc:
            return await self._serve_stale_or_failing_async(
                cache_key, FailureReason.OTHER, str(exc)
            )

        # --- Store in cache ---
        entry = {"response": raw, "_fetched_at": time.time()}
        await self._cache.set(cache_key, entry, _CACHE_TTL)
        # Stale backup survives 7× primary TTL for degraded-mode fallback.
        await self._cache.set(f"{cache_key}:stale", entry, _CACHE_TTL * 7)

        return _parse_vt_response(raw, cached=False, cache_age_seconds=None)

    async def _fetch(self, indicator: Indicator) -> dict:
        """Perform the lookup. Raises _VT* exceptions; 404 returns sentinel dict."""
        if self._fixture_loader is not None:
            result = self._fixture_loader(indicator.type.value, indicator.value)
            # None from fixture loader means "not in VT database" (like a 404).
            return result if result is not None else {"_not_found": True}

        if self._rate_limiter is not None:
            await self._rate_limiter.acquire()

        url = _endpoint_url(indicator)
        try:
            async with create_http_client(self._timeout, "virustotal") as client:
                resp = await client.get(url, headers={"x-apikey": self._api_key})
        except Exception as exc:
            # Translate httpx transport errors without importing httpx directly.
            etype = type(exc).__qualname__
            if "Timeout" in etype:
                raise _VTTransportError(f"timeout: {exc}") from exc
            if any(t in etype for t in ("NetworkError", "ConnectError", "RemoteProtocol")):
                raise _VTTransportError(f"network error: {exc}") from exc
            raise

        if resp.status_code == 401:
            raise _VTAuthError("Invalid VT API key (401)")
        if resp.status_code == 429:
            raise _VTRateLimit("VT rate limit (429)")
        if resp.status_code == 404:
            # Not a CB failure — indicator simply not indexed in VT.
            return {"_not_found": True}
        resp.raise_for_status()
        return resp.json()

    async def _serve_stale_or_failing_async(
        self, cache_key: str, reason: FailureReason, detail: str
    ) -> EnrichmentResult:
        stale = await self._cache.get(f"{cache_key}:stale")
        if stale is not None:
            age = int(time.time() - stale.get("_fetched_at", 0.0))
            logger.warning("vt_stale_cache_served", reason=reason.value, age_s=age)
            return _parse_vt_response(stale["response"], cached=True, cache_age_seconds=age)
        return EnrichmentResult.failing(_SOURCE, reason, detail)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _endpoint_url(indicator: Indicator) -> str:
    if indicator.type is IndicatorType.IP:
        return f"{_VT_BASE}/ip_addresses/{indicator.value}"
    return f"{_VT_BASE}/domains/{indicator.value}"


def _parse_vt_response(
    raw: dict,
    *,
    cached: bool,
    cache_age_seconds: int | None,
) -> EnrichmentResult:
    """Build EnrichmentResult from a VT API response dict."""
    if raw.get("_not_found"):
        return EnrichmentResult(
            source=_SOURCE,
            status=EnrichmentStatus.CONTRIBUTED,
            data={"malicious_count": 0, "total_engines": 0, "not_in_database": True},
            summary="Not in VT database",
            failure_reason=None,
            failure_detail=None,
            last_success_at=datetime.now(UTC),
            cached=cached,
            cache_age_seconds=cache_age_seconds,
        )

    try:
        attrs = raw["data"]["attributes"]
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0
        reputation = attrs.get("reputation", None)

        data = {
            "malicious_count": malicious,
            "suspicious_count": suspicious,
            "total_engines": total,
            "reputation": reputation,
            "last_analysis_stats": stats,
        }
        flagged = malicious + suspicious
        summary = f"{flagged}/{total} vendors flagged" if total > 0 else "No detections"
    except (KeyError, TypeError):
        return EnrichmentResult.failing(
            _SOURCE,
            FailureReason.MALFORMED_RESPONSE,
            "Unexpected VT API response structure",
        )

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
