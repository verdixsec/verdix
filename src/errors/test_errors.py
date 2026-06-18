# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Tests for the AppError class hierarchy."""
from __future__ import annotations

import pytest

from src.errors import (
    AppError,
    CircuitBreakerOpen,
    EventStoreWriteFailed,
    EveParseError,
    LLMUnavailable,
    MaxMindDBMissing,
    OperationalError,
    ProgrammerError,
    RDAPTimeout,
    SuricataConfigInvalid,
    SuricataConfigMissing,
    VTAuthFailed,
    VTRateLimited,
)

# ---------------------------------------------------------------------------
# Hierarchy
# ---------------------------------------------------------------------------


def test_operational_error_is_app_error() -> None:
    assert issubclass(OperationalError, AppError)


def test_programmer_error_is_app_error() -> None:
    assert issubclass(ProgrammerError, AppError)


def test_all_concrete_errors_are_operational() -> None:
    concrete = [
        EveParseError,
        SuricataConfigInvalid,
        SuricataConfigMissing,
        LLMUnavailable,
        VTRateLimited,
        VTAuthFailed,
        RDAPTimeout,
        MaxMindDBMissing,
        EventStoreWriteFailed,
        CircuitBreakerOpen,
    ]
    for cls in concrete:
        assert issubclass(cls, OperationalError), f"{cls.__name__} should be OperationalError"
        assert issubclass(cls, AppError), f"{cls.__name__} should be AppError"


def test_all_concrete_errors_are_exception() -> None:
    err = EveParseError("bad json")
    assert isinstance(err, Exception)


# ---------------------------------------------------------------------------
# Machine-readable codes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cls, expected_code",
    [
        (EveParseError, "EVE_PARSE_ERROR"),
        (SuricataConfigInvalid, "SURICATA_CONFIG_INVALID"),
        (SuricataConfigMissing, "SURICATA_CONFIG_MISSING"),
        (LLMUnavailable, "LLM_UNAVAILABLE"),
        (VTRateLimited, "VT_RATE_LIMITED"),
        (VTAuthFailed, "VT_AUTH_FAILED"),
        (RDAPTimeout, "RDAP_TIMEOUT"),
        (MaxMindDBMissing, "MAXMIND_DB_MISSING"),
        (EventStoreWriteFailed, "EVENT_STORE_WRITE_FAILED"),
        (CircuitBreakerOpen, "CIRCUIT_BREAKER_OPEN"),
        (OperationalError, "OPERATIONAL_ERROR"),
        (ProgrammerError, "PROGRAMMER_ERROR"),
    ],
)
def test_error_code(cls: type[AppError], expected_code: str) -> None:
    err = cls("test message")
    assert err.code == expected_code


# ---------------------------------------------------------------------------
# Construction and str representation
# ---------------------------------------------------------------------------


def test_message_stored_on_error() -> None:
    err = EveParseError("unexpected end of JSON")
    assert err.message == "unexpected end of JSON"


def test_str_includes_code_and_message() -> None:
    err = LLMUnavailable("ollama not reachable")
    s = str(err)
    assert "LLM_UNAVAILABLE" in s
    assert "ollama not reachable" in s


def test_detail_stored_and_included_in_str() -> None:
    err = SuricataConfigMissing(
        "config file not found", detail="/host/suricata/config/suricata.yaml"
    )
    assert err.detail == "/host/suricata/config/suricata.yaml"
    assert "/host/suricata/config/suricata.yaml" in str(err)


def test_detail_is_optional() -> None:
    err = VTRateLimited("rate limit exceeded")
    assert err.detail is None
    assert "(" not in str(err)


def test_cause_is_stored_and_chained() -> None:
    original = ValueError("underlying network error")
    err = RDAPTimeout("RDAP query timed out", cause=original)
    assert err.cause is original
    assert err.__cause__ is original


def test_cause_is_optional() -> None:
    err = CircuitBreakerOpen("VT circuit breaker open")
    assert err.cause is None


def test_repr_includes_class_name_and_code() -> None:
    err = MaxMindDBMissing("database not found")
    r = repr(err)
    assert "MaxMindDBMissing" in r
    assert "MAXMIND_DB_MISSING" in r


# ---------------------------------------------------------------------------
# raise ... from cause pattern
# ---------------------------------------------------------------------------


def test_raise_with_cause_preserves_traceback() -> None:
    original = ConnectionError("refused")
    with pytest.raises(LLMUnavailable) as exc_info:
        try:
            raise original
        except ConnectionError as e:
            raise LLMUnavailable("ollama unreachable", cause=e) from e
    assert exc_info.value.__cause__ is original


# ---------------------------------------------------------------------------
# ProgrammerError is never caught by OperationalError handlers
# ---------------------------------------------------------------------------


def test_programmer_error_not_caught_as_operational() -> None:
    with pytest.raises(ProgrammerError):
        try:
            raise ProgrammerError("invariant violated")
        except OperationalError:
            pass  # should NOT reach here
