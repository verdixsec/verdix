# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Application error hierarchy.

Import from here at all call sites:
    from src.errors import EveParseError, LLMUnavailable, OperationalError
"""
from src.errors.base import AppError, OperationalError, ProgrammerError
from src.errors.operational import (
    CircuitBreakerOpen,
    EventStoreWriteFailed,
    EveParseError,
    LLMUnavailable,
    MaxMindDBMissing,
    RDAPTimeout,
    SuricataConfigInvalid,
    SuricataConfigMissing,
    VTAuthFailed,
    VTRateLimited,
)

__all__ = [
    "AppError",
    "CircuitBreakerOpen",
    "EveParseError",
    "EventStoreWriteFailed",
    "LLMUnavailable",
    "MaxMindDBMissing",
    "OperationalError",
    "ProgrammerError",
    "RDAPTimeout",
    "SuricataConfigInvalid",
    "SuricataConfigMissing",
    "VTAuthFailed",
    "VTRateLimited",
]
