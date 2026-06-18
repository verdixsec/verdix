# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Static mapping of Suricata alert categories to role-assignment patterns.

Each entry is (category_substring, pattern, base_confidence).
Matching is case-insensitive substring search on alert.category from EVE JSON.
First match wins — order matters (more specific strings before generic ones).

Patterns:
  outbound_cnc    — internal host calling external CnC/trojan infrastructure
  inbound_attack  — external attacker targeting internal service/host
  attack_response — external CnC server responding to compromised internal host
  scan            — network scan; scanner is the attacker
  unknown         — insufficient signal; falls through to low/ambiguous confidence

This list is versioned here and referenced by the assigner. As the ET ruleset
evolves, new category strings are added here rather than in the assigner logic.
"""
from __future__ import annotations

CATEGORY_RULES: list[tuple[str, str, str]] = [
    # ── Outbound CnC / trojan (Pattern B) ─────────────────────────────────────
    ("command and control", "outbound_cnc", "medium"),
    ("trojan", "outbound_cnc", "medium"),
    ("malware", "outbound_cnc", "medium"),
    # ── Inbound attack / exploit (Pattern A) ──────────────────────────────────
    ("web application attack", "inbound_attack", "medium"),
    ("attempted administrator privilege", "inbound_attack", "medium"),
    ("attempted user privilege", "inbound_attack", "medium"),
    ("successful administrator privilege", "inbound_attack", "medium"),
    ("successful user privilege", "inbound_attack", "medium"),
    ("exploit kit", "inbound_attack", "medium"),
    ("shellcode detect", "inbound_attack", "medium"),
    ("denial of service", "inbound_attack", "medium"),
    ("network trojan", "inbound_attack", "medium"),
    # ── Attack response (Pattern D) ────────────────────────────────────────────
    ("attack response", "attack_response", "medium"),
    # ── Scan ──────────────────────────────────────────────────────────────────
    ("network scan", "scan", "medium"),
    # ── Low-signal / ambiguous ─────────────────────────────────────────────────
    ("policy violation", "unknown", "low"),
    ("potentially bad traffic", "unknown", "low"),
    ("misc activity", "unknown", "low"),
    ("not suspicious", "unknown", "low"),
    ("unknown traffic", "unknown", "low"),
    ("decode of an rpc", "unknown", "low"),
    ("inappropriate content", "unknown", "low"),
]


def detect_pattern(category: str) -> tuple[str, str]:
    """Return (pattern, base_confidence) for a Suricata category string.

    Falls through to ("unknown", "low") when no rule matches.
    """
    lower = category.lower()
    for substring, pattern, confidence in CATEGORY_RULES:
        if substring in lower:
            return pattern, confidence
    return "unknown", "low"
