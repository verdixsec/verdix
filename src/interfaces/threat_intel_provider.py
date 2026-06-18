# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""ThreatIntelProvider interface — abstract over enrichment lookups.

Concrete implementations (v0.1):
  src/enrichment/virustotal/client.py — VirusTotal (IP, domain)
  src/enrichment/maxmind/client.py    — DB-IP / MaxMind GeoIP (IP only)
  src/enrichment/rdap/client.py       — RDAP domain registration (domain only)

v1+ additions: MISP, GreyNoise, etc.

Application code imports this Protocol only, never a concrete client.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from src.enrichment.models import EnrichmentResult, Indicator


@runtime_checkable
class ThreatIntelProvider(Protocol):
    """Enrichment lookup for a single indicator."""

    async def lookup(self, indicator: Indicator) -> EnrichmentResult:
        """Return an EnrichmentResult for the given indicator.

        Never raises. If the source is not configured, returns NOT_CONFIGURED.
        If configured but the call fails, returns FAILING with failure_reason set.
        If successful, returns CONTRIBUTED with data and summary populated.
        """
        ...
