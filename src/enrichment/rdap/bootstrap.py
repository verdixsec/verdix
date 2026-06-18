# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""IANA RDAP bootstrap registry — maps TLDs to their RDAP base URLs.

The IANA bootstrap registry (dns.json) is cached in SQLite (or in-memory)
and refreshed weekly. On cache miss the download is performed synchronously.
If the download fails and no cache exists, a minimal hardcoded fallback
covers the most common TLDs (.com, .net, .org).

RFC 7484 defines the bootstrap process.
IANA registry URL: https://data.iana.org/rdap/dns.json
"""
from __future__ import annotations

import asyncio

import structlog

from src.interfaces.cache import Cache

logger = structlog.get_logger(__name__)

_IANA_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"
_CACHE_KEY = "rdap:bootstrap"
_CACHE_TTL = 7 * 24 * 3600  # 7 days

# Fallback covers the most common TLDs when download fails and no cache exists.
_FALLBACK_SERVICES: dict[str, str] = {
    "com": "https://rdap.verisign.com/com/v1/",
    "net": "https://rdap.verisign.com/net/v1/",
    "org": "https://rdap.publicinterestregistry.org/rdap/",
    "info": "https://rdap.afilias.net/rdap/info/",
    "io": "https://rdap.nic.io/",
    "co": "https://rdap.nic.co/",
    "uk": "https://rdap.nominet.uk/uk/",
    "de": "https://rdap.denic.de/",
    "fr": "https://rdap.afnic.fr/",
    "nl": "https://rdap.sidn.nl/",
    "eu": "https://rdap.eu/",
    "biz": "https://rdap.nic.biz/",
    "us": "https://rdap.nic.us/",
    "mobi": "https://rdap.nic.mobi/",
}


class RDAPBootstrap:
    """Manages the IANA RDAP bootstrap registry with caching.

    Args:
        cache:   Cache instance (SQLiteCache in production, InMemoryTTLCache in tests).
        timeout: HTTP timeout for bootstrap download.
    """

    def __init__(self, cache: Cache, *, timeout: float = 10.0) -> None:
        self._cache = cache
        self._timeout = timeout
        self._tld_map: dict[str, str] | None = None  # in-process cache
        self._lock: asyncio.Lock = asyncio.Lock()

    async def get_base_url(self, domain: str) -> str | None:
        """Return the RDAP base URL for the given domain's TLD, or None if unknown."""
        tld = _extract_tld(domain)
        if not tld:
            return None

        tld_map = await self._get_tld_map()
        return tld_map.get(tld)

    async def _get_tld_map(self) -> dict[str, str]:
        # Fast path — already loaded in this process.
        if self._tld_map is not None:
            return self._tld_map

        # Slow path — acquire lock so concurrent domain lookups on the same
        # alert don't each trigger a separate bootstrap download (thundering herd).
        async with self._lock:
            # Re-check inside lock: another coroutine may have populated it.
            if self._tld_map is not None:
                return self._tld_map

            cached = await self._cache.get(_CACHE_KEY)
            if cached is not None:
                self._tld_map = cached
                return cached

            # Download fresh bootstrap data.
            tld_map = await self._download()
            await self._cache.set(_CACHE_KEY, tld_map, _CACHE_TTL)
            self._tld_map = tld_map
            return tld_map

    async def _download(self) -> dict[str, str]:
        """Download the IANA bootstrap registry and parse TLD → URL mapping."""
        from src.infra.http.factory import create_http_client

        # Network/HTTP errors: use fallback.  Programmer errors: propagate.
        try:
            async with create_http_client(self._timeout, "rdap-bootstrap") as client:
                resp = await client.get(_IANA_BOOTSTRAP_URL)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            logger.warning("rdap_bootstrap_download_failed", error=str(exc))
            return _FALLBACK_SERVICES.copy()

        # Parsing is our own code — let programmer errors propagate.
        tld_map: dict[str, str] = {}
        for service in data.get("services", []):
            if len(service) < 2:
                continue
            tlds, urls = service[0], service[1]
            if not urls:
                continue
            base_url = urls[0]  # first URL is preferred
            for tld in tlds:
                tld_map[tld.lower()] = base_url

        logger.info("rdap_bootstrap_downloaded", tld_count=len(tld_map))
        return tld_map


def _extract_tld(domain: str) -> str | None:
    """Extract the effective TLD (last label) from a domain name."""
    domain = domain.lower().rstrip(".")
    parts = domain.split(".")
    if len(parts) < 2:
        return None
    return parts[-1]
