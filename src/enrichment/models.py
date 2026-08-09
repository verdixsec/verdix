# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Enrichment data models — uniform return type for all ThreatIntelProvider implementations.

ADR-007: three-state enrichment-source ledger (CONTRIBUTED / FAILING / NOT_CONFIGURED).
Every enrichment client returns EnrichmentResult; the ledger is built from these results.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum


class EnrichmentStatus(Enum):
    CONTRIBUTED = "contributed"          # source returned data, used in verdict
    FAILING = "failing"                  # configured but call failed
    NOT_CONFIGURED = "not_configured"    # source not set up at all


class FailureReason(Enum):
    RATE_LIMITED = "RATE_LIMITED"
    TIMEOUT = "TIMEOUT"
    NETWORK_ERROR = "NETWORK_ERROR"
    AUTH_FAILED = "AUTH_FAILED"
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE"
    CIRCUIT_BREAKER_OPEN = "CIRCUIT_BREAKER_OPEN"
    OTHER = "OTHER"


class IndicatorType(Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    URL = "url"


@dataclass
class Indicator:
    """A single indicator to enrich (IP, domain, hash, or URL)."""

    type: IndicatorType
    value: str

    @property
    def cache_key_suffix(self) -> str:
        return f"{self.type.value}:{self.value}"


@dataclass
class EnrichmentResult:
    """Uniform return type from all ThreatIntelProvider.lookup() calls.

    Cache staleness is a *property* of CONTRIBUTED (cached=True, cache_age_seconds set),
    not a separate state. Three states is the right cognitive load for analysts.
    """

    source: str                          # "virustotal", "rdap", "geoip"
    status: EnrichmentStatus
    data: dict | None                    # enrichment payload, only if CONTRIBUTED
    summary: str | None                  # one-line analyst-facing summary
    failure_reason: FailureReason | None  # only if FAILING
    failure_detail: str | None           # human-readable detail
    last_success_at: datetime | None
    queried_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    cached: bool = False
    cache_age_seconds: int | None = None

    @classmethod
    def not_configured(cls, source: str) -> EnrichmentResult:
        return cls(
            source=source,
            status=EnrichmentStatus.NOT_CONFIGURED,
            data=None,
            summary=None,
            failure_reason=None,
            failure_detail=None,
            last_success_at=None,
        )

    @classmethod
    def failing(
        cls,
        source: str,
        reason: FailureReason,
        detail: str,
        last_success_at: datetime | None = None,
    ) -> EnrichmentResult:
        return cls(
            source=source,
            status=EnrichmentStatus.FAILING,
            data=None,
            summary=None,
            failure_reason=reason,
            failure_detail=detail,
            last_success_at=last_success_at,
        )
