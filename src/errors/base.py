# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Base AppError class hierarchy.

All errors raised by application code must be instances of AppError, never
raw Exception. Two categories:

  OperationalError — external failures that are expected in production and
      must be handled gracefully. Examples: LLM timeout, VT rate limit, missing
      config file. Catch these, log a warning, and serve a degraded result.

  ProgrammerError — invariant violations and contract breaches that should
      never occur in production. Examples: None passed where required, caller
      broke an interface contract. Do not catch these; let them crash so the
      defect is surfaced immediately during development.

Every error carries:
  code    — machine-readable string constant, stable across releases
  message — human-readable description (safe to surface in logs, not in UI)
  detail  — optional extra context (e.g. file path, indicator value)
  cause   — the original exception, if any (set via raise ... from cause)
"""
from __future__ import annotations


class AppError(Exception):
    """Base class for all application errors."""

    code: str = "APP_ERROR"

    def __init__(
        self,
        message: str,
        *,
        detail: str | None = None,
        cause: BaseException | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail
        self.cause = cause
        if cause is not None:
            self.__cause__ = cause

    def __str__(self) -> str:
        parts = [f"[{self.code}] {self.message}"]
        if self.detail:
            parts.append(f"({self.detail})")
        return " ".join(parts)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r}, message={self.message!r})"


class OperationalError(AppError):
    """Expected runtime failure — catch, log warn/error, serve degraded result."""

    code = "OPERATIONAL_ERROR"


class ProgrammerError(AppError):
    """Invariant violation — do not catch; surface immediately as a crash."""

    code = "PROGRAMMER_ERROR"
