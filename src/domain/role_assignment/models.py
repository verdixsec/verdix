# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""RoleAssignment dataclass — output of the deterministic role assigner (ADR-010)."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


@dataclass
class RoleAssignment:
    """Four-role model for a single Suricata alert.

    initiator/responder — network 5-tuple direction facts (always populated).
    attacker/victim     — security narrative (nullable when ambiguous).

    Captured per alert as prompt context for the LLM.  The LLM can disagree
    with the deterministic assignment when broader context contradicts it.
    """

    initiator_ip: str
    responder_ip: str
    attacker_ip: str | None
    victim_ip: str | None
    confidence: Literal["high", "medium", "low", "ambiguous"]
    reasoning: str
    signals_used: list[str]
