# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Concrete operational error classes for weeks 3-4 features.

All are OperationalError subclasses — expected runtime failures that callers
must handle with a degraded-mode fallback, never by crashing.
"""
from __future__ import annotations

from src.errors.base import OperationalError


class EveParseError(OperationalError):
    """A line from eve.json could not be parsed as valid JSON or a known event type."""

    code = "EVE_PARSE_ERROR"


class SuricataConfigInvalid(OperationalError):
    """suricata.yaml is present but malformed or missing a required field (e.g. HOME_NET)."""

    code = "SURICATA_CONFIG_INVALID"


class SuricataConfigMissing(OperationalError):
    """suricata.yaml does not exist at the configured path. Application refuses to start."""

    code = "SURICATA_CONFIG_MISSING"


class LLMUnavailable(OperationalError):
    """The LLM backend (Ollama) is unreachable, timed out, or returned an unrecoverable error."""

    code = "LLM_UNAVAILABLE"


class VTRateLimited(OperationalError):
    """VirusTotal returned HTTP 429. Serve stale cache if available, else mark FAILING."""

    code = "VT_RATE_LIMITED"


class VTAuthFailed(OperationalError):
    """VirusTotal returned HTTP 401 / 403. API key is absent or invalid."""

    code = "VT_AUTH_FAILED"


class RDAPTimeout(OperationalError):
    """RDAP registry query timed out or failed with a network error."""

    code = "RDAP_TIMEOUT"


class MaxMindDBMissing(OperationalError):
    """The MaxMind GeoLite2 database file does not exist at the configured path."""

    code = "MAXMIND_DB_MISSING"


class EventStoreWriteFailed(OperationalError):
    """A write to the EventStore (SQLite) failed.

    Circuit breaker may open after repeated failures.
    """

    code = "EVENT_STORE_WRITE_FAILED"


class CircuitBreakerOpen(OperationalError):
    """A circuit breaker is open — the downstream dependency is in cooldown.

    Raise this instead of attempting a call when pybreaker reports the circuit is open.
    """

    code = "CIRCUIT_BREAKER_OPEN"
