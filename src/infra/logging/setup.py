# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Configure structlog for structured JSON output to stdout.

Call configure_logging() exactly once at application startup before any log
lines are emitted. Calling it multiple times is safe (last call wins).
"""
from __future__ import annotations

import logging
import sys

import structlog


def configure_logging(log_level: str = "INFO") -> None:
    """Wire up structlog for JSON output to stdout at the given log level.

    Processor chain (in order):
      1. Merge contextvars (alert_id, trace_id, sensor_id, purpose, …)
      2. Add log level string ("info", "warning", "error", "debug")
      3. Add logger name (module that called get_logger)
      4. ISO-8601 timestamp
      5. Render exception info if present
      6. Render stack info if present
      7. JSON serialise to stdout

    Third-party stdlib logging (httpx, PyYAML, etc.) is also routed to stdout
    at the same level so all log output is a single uniform JSON stream.

    Never log PII, payload content, or credentials.
    IP addresses and hostnames are acceptable; user data and tokens are not.
    """
    numeric_level = logging.getLevelName(log_level.upper())

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_log_level,
            # add_logger_name is stdlib-only; omitted here (PrintLoggerFactory has no .name)
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.ExceptionRenderer(),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(numeric_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False,
    )

    # Route stdlib logging through the same stdout stream.
    # format="%(message)s" avoids double-formatting since structlog renders the line.
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=numeric_level,
        force=True,
    )
