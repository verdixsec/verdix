# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Structured logging infrastructure.

Usage at call sites:
    import structlog
    logger = structlog.get_logger(__name__)
    logger.info("alert_ingested", alert_id="formbook-001", sensor_id=1)

Context binding (call once at the start of each alert's processing):
    from src.infra.logging.context import bind_alert_context, clear_alert_context
    trace_id = bind_alert_context(alert_id="formbook-001")
    ...
    clear_alert_context()
"""
from src.infra.logging.context import bind_alert_context, bind_http_context, clear_alert_context
from src.infra.logging.setup import configure_logging

__all__ = [
    "bind_alert_context",
    "bind_http_context",
    "clear_alert_context",
    "configure_logging",
]
