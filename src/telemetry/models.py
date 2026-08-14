# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Versioned payload dataclasses for feedback submissions.

Two user-initiated submission types share one payload shape and one endpoint:
feedback and deletion requests. schema_version must be incremented whenever a
field is added or removed so the server can parse old payloads correctly after
app upgrades.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

APP_VERSION = "0.1.4"
SCHEMA_VERSION = 2

# The only submission types the app emits and the receiver accepts. The
# discriminator is the seam the production backend keys off of.
ACCEPTED_SUBMISSION_TYPES = frozenset({"feedback", "deletion_request"})


@dataclass
class HardwareContext:
    ram_gb: int | None
    cpu_cores: int | None
    gpu_present: bool


@dataclass
class SubmissionContext:
    model: str | None = None
    enrichment_sources: list[str] = field(default_factory=list)
    hardware: HardwareContext | None = None
    days_since_install: int | None = None


@dataclass
class SubmissionMetrics:
    alerts_processed_total: int = 0
    verdicts_likely_fp: int = 0
    verdicts_suspicious: int = 0
    verdicts_likely_tp: int = 0
    agreement_rate: float | None = None
    latency_p95_ms: int | None = None


@dataclass
class FeedbackPayload:
    """Payload sent when the user clicks Send Feedback.

    The server adds install_id and submitted_at before forwarding to the
    feedback endpoint so the browser never sees the install UUID directly.
    """

    feedback_text: str
    context: SubmissionContext | None = None
    metrics: SubmissionMetrics | None = None

    # Server-stamped fields — populated by /api/feedback before forwarding.
    schema_version: int = SCHEMA_VERSION
    submission_type: str = "feedback"
    app_version: str = APP_VERSION
    install_id: str = ""
    submitted_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # Remove null top-level keys to keep the payload clean.
        return {k: v for k, v in d.items() if v is not None and v != ""}
