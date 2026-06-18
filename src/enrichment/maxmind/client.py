# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""GeoIP enrichment client — DB-IP Community Edition (default) or MaxMind GeoLite2.

Ships DB-IP Community Edition databases in the Docker image (CC BY 4.0 license,
redistribution permitted). Customers who already have MaxMind GeoLite2 can point
to their existing files via VX_GEOIP_COUNTRY_DB_PATH / VX_GEOIP_ASN_DB_PATH.

Both DB-IP and MaxMind use the MMDB format; the geoip2 library reads either
transparently. One code path, two database sources.

Key behaviours:
  - IP indicators only; domain, hash, URL return NOT_CONFIGURED.
  - No internet required — local database file.
  - NOT_CONFIGURED if the database file path is not set or file does not exist.
  - No circuit breaker needed (local reads never trigger network failures).
  - Returns country code + ASN + ASN org in summary: "US, AS15169 Google LLC"
  - Missing country or ASN data degrades gracefully (returns what's available).
"""
from __future__ import annotations

import os
from datetime import UTC, datetime

import structlog

from src.enrichment.models import (
    EnrichmentResult,
    EnrichmentStatus,
    Indicator,
    IndicatorType,
)

logger = structlog.get_logger(__name__)

_SOURCE = "geoip"

# Default paths for DB-IP Community Edition databases baked into the Docker image.
_DEFAULT_COUNTRY_DB = os.environ.get(
    "VX_GEOIP_COUNTRY_DB_PATH",
    "/var/lib/verdix/geoip/dbip-country-lite.mmdb",
)
_DEFAULT_ASN_DB = os.environ.get(
    "VX_GEOIP_ASN_DB_PATH",
    "/var/lib/verdix/geoip/dbip-asn-lite.mmdb",
)


class GeoIPClient:
    """GeoIP enrichment backed by MMDB database files (DB-IP or MaxMind).

    Args:
        country_db_path: Path to a country/city MMDB file.
        asn_db_path:     Path to an ASN MMDB file.
    """

    def __init__(
        self,
        *,
        country_db_path: str = _DEFAULT_COUNTRY_DB,
        asn_db_path: str = _DEFAULT_ASN_DB,
    ) -> None:
        self._country_db_path = country_db_path
        self._asn_db_path = asn_db_path
        self._country_reader = None
        self._asn_reader = None
        self._init_attempted = False

    def _init_readers(self) -> None:
        """Lazy-initialise readers on first lookup. Logs if files are missing."""
        if self._init_attempted:
            return
        self._init_attempted = True

        try:
            import geoip2.database  # type: ignore[import]
        except ImportError:
            logger.warning("geoip2_not_installed", hint="pip install geoip2")
            return

        import os.path

        if os.path.isfile(self._country_db_path):
            try:
                self._country_reader = geoip2.database.Reader(self._country_db_path)
                logger.info("geoip_country_db_loaded", path=self._country_db_path)
            except Exception as exc:
                logger.warning(
                    "geoip_country_db_open_failed",
                    path=self._country_db_path,
                    error=str(exc),
                )
        else:
            logger.warning("geoip_country_db_not_found", path=self._country_db_path)

        if os.path.isfile(self._asn_db_path):
            try:
                self._asn_reader = geoip2.database.Reader(self._asn_db_path)
                logger.info("geoip_asn_db_loaded", path=self._asn_db_path)
            except Exception as exc:
                logger.warning("geoip_asn_db_open_failed", path=self._asn_db_path, error=str(exc))
        else:
            logger.warning("geoip_asn_db_not_found", path=self._asn_db_path)

    async def lookup(self, indicator: Indicator) -> EnrichmentResult:
        """Return GeoIP data for IP indicators. Never raises."""
        if indicator.type is not IndicatorType.IP:
            return EnrichmentResult.not_configured(_SOURCE)

        self._init_readers()

        if self._country_reader is None and self._asn_reader is None:
            return EnrichmentResult.not_configured(_SOURCE)

        ip = indicator.value
        country_code: str | None = None
        country_name: str | None = None
        asn: int | None = None
        asn_org: str | None = None

        # Country lookup
        if self._country_reader is not None:
            try:
                record = self._country_reader.country(ip)
                country_code = record.country.iso_code
                country_name = record.country.name
            except Exception:
                pass  # Private/reserved IPs, loopback, etc. — not a failure

        # ASN lookup
        if self._asn_reader is not None:
            try:
                record = self._asn_reader.asn(ip)
                asn = record.autonomous_system_number
                asn_org = record.autonomous_system_organization
            except Exception:
                pass

        data = {
            "country_code": country_code,
            "country_name": country_name,
            "asn": asn,
            "asn_org": asn_org,
        }

        parts: list[str] = []
        if country_code:
            parts.append(country_code)
        if asn and asn_org:
            parts.append(f"AS{asn} {asn_org}")
        elif asn:
            parts.append(f"AS{asn}")

        if not parts:
            # Check if private/reserved before reporting not_configured — the client
            # IS configured, these IPs just aren't in any GeoIP database by design.
            import ipaddress
            try:
                addr = ipaddress.ip_address(ip)
                if addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved:
                    logger.info("geoip_lookup", ip=ip, summary="Private IP")
                    return EnrichmentResult(
                        source=_SOURCE,
                        status=EnrichmentStatus.CONTRIBUTED,
                        data={"note": "private_ip"},
                        summary="Private IP",
                        failure_reason=None,
                        failure_detail=None,
                        last_success_at=datetime.now(UTC),
                        cached=False,
                        cache_age_seconds=None,
                    )
            except ValueError:
                pass
            return EnrichmentResult.not_configured(_SOURCE)

        summary = ", ".join(parts)
        logger.info("geoip_lookup", ip=ip, summary=summary)

        return EnrichmentResult(
            source=_SOURCE,
            status=EnrichmentStatus.CONTRIBUTED,
            data=data,
            summary=summary,
            failure_reason=None,
            failure_detail=None,
            last_success_at=datetime.now(UTC),
            cached=False,
            cache_age_seconds=None,
        )

    def close(self) -> None:
        """Release MMDB file handles. Call at application shutdown."""
        if self._country_reader is not None:
            self._country_reader.close()
        if self._asn_reader is not None:
            self._asn_reader.close()
