# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Tests for the deterministic role assigner (ADR-010)."""
from __future__ import annotations

import ipaddress
from datetime import datetime

from src.domain.role_assignment.assigner import assign_roles
from src.infra.suricata_config.models import SuricataConfig

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

HOME_NET = [ipaddress.IPv4Network("10.0.0.0/8")]


def _config(home_net=None) -> SuricataConfig:
    nets = home_net or HOME_NET
    return SuricataConfig(
        home_net=nets,
        external_net=[],
        server_groups={},
        port_groups={},
        rule_file_paths=[],
        rule_file_summaries={},
        config_file_paths_read=[],
        read_at=datetime(2026, 5, 9),
        raw_yaml_hash="test",
    )


def _alert(
    src_ip: str = "10.0.0.1",
    dest_ip: str = "185.220.101.45",
    category: str = "Malware Command and Control Activity Detected",
    *,
    target: str | None = None,
    attack_target: list[str] | None = None,
    signature: str = "ET TROJAN Test",
) -> dict:
    alert_sub: dict = {"category": category, "signature": signature, "severity": 1}
    if target is not None:
        alert_sub["target"] = target
    if attack_target is not None:
        alert_sub["metadata"] = {"attack_target": attack_target}
    return {
        "event_type": "alert",
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "alert": alert_sub,
    }


# ---------------------------------------------------------------------------
# Signal 1: target field (highest priority, confidence=high)
# ---------------------------------------------------------------------------


def test_target_src_ip_makes_src_victim():
    raw = _alert(
        src_ip="10.0.0.1",
        dest_ip="185.0.0.1",
        category="Misc Activity",  # would be ambiguous without target
        target="src_ip",
    )
    result = assign_roles(raw, _config())
    assert result.victim_ip == "10.0.0.1"
    assert result.attacker_ip == "185.0.0.1"
    assert result.confidence == "high"
    assert "target_field" in result.signals_used


def test_target_dest_ip_makes_dest_victim():
    raw = _alert(
        src_ip="185.0.0.1",
        dest_ip="10.0.0.50",
        category="Misc Activity",
        target="dest_ip",
    )
    result = assign_roles(raw, _config())
    assert result.victim_ip == "10.0.0.50"
    assert result.attacker_ip == "185.0.0.1"
    assert result.confidence == "high"
    assert "target_field" in result.signals_used


def test_target_field_overrides_category():
    """target field wins even when category alone would give the opposite assignment."""
    raw = _alert(
        src_ip="10.0.0.1",
        dest_ip="185.0.0.1",
        # CnC category would normally mark src (internal) as victim,
        # but target field says dest is the target.
        category="Malware Command and Control Activity Detected",
        target="dest_ip",
    )
    result = assign_roles(raw, _config())
    assert result.victim_ip == "185.0.0.1"
    assert result.attacker_ip == "10.0.0.1"
    assert result.confidence == "high"


# ---------------------------------------------------------------------------
# Pattern B — internal compromised host calling out (CnC / trojan)
# ---------------------------------------------------------------------------


def test_pattern_b_internal_cnc_callout():
    """Classic case: internal host (infected) calling external CnC server."""
    raw = _alert(
        src_ip="10.0.0.1",       # HOME_NET — the infected victim
        dest_ip="185.220.101.45",  # external — the CnC attacker
        category="Malware Command and Control Activity Detected",
    )
    result = assign_roles(raw, _config())
    assert result.initiator_ip == "10.0.0.1"
    assert result.responder_ip == "185.220.101.45"
    assert result.attacker_ip == "185.220.101.45"
    assert result.victim_ip == "10.0.0.1"
    assert result.confidence == "medium"
    assert "rule_category" in result.signals_used
    assert "home_net_membership" in result.signals_used


def test_pattern_b_trojan_category():
    raw = _alert(
        src_ip="10.0.0.5",
        dest_ip="1.2.3.4",
        category="A Network Trojan was Detected",
    )
    result = assign_roles(raw, _config())
    assert result.attacker_ip == "1.2.3.4"
    assert result.victim_ip == "10.0.0.5"
    assert result.confidence == "medium"


def test_pattern_b_reversed_direction_low_confidence():
    """External→internal on a CnC category — unusual, assigned low confidence."""
    raw = _alert(
        src_ip="185.0.0.1",  # external
        dest_ip="10.0.0.2",  # internal
        category="Malware Command and Control Activity Detected",
    )
    result = assign_roles(raw, _config())
    assert result.attacker_ip == "185.0.0.1"
    assert result.victim_ip == "10.0.0.2"
    assert result.confidence == "low"


# ---------------------------------------------------------------------------
# Pattern A — external attacker, internal victim (inbound attack / exploit)
# ---------------------------------------------------------------------------


def test_pattern_a_web_attack():
    raw = _alert(
        src_ip="203.0.113.1",  # external attacker
        dest_ip="10.0.0.80",   # internal web server victim
        category="Web Application Attack",
        signature="ET WEB_SERVER ...",
    )
    result = assign_roles(raw, _config())
    assert result.attacker_ip == "203.0.113.1"
    assert result.victim_ip == "10.0.0.80"
    assert result.confidence == "medium"


def test_pattern_a_exploit():
    raw = _alert(
        src_ip="198.51.100.5",
        dest_ip="10.0.0.22",
        category="Exploit Kit Activity Detected",
    )
    result = assign_roles(raw, _config())
    assert result.attacker_ip == "198.51.100.5"
    assert result.victim_ip == "10.0.0.22"
    assert result.confidence == "medium"


def test_pattern_a_internal_to_external_low_confidence():
    """Internal→external on an inbound-attack category — low confidence."""
    raw = _alert(
        src_ip="10.0.0.5",
        dest_ip="93.184.216.34",
        category="Web Application Attack",
    )
    result = assign_roles(raw, _config())
    assert result.attacker_ip == "10.0.0.5"
    assert result.victim_ip == "93.184.216.34"
    assert result.confidence == "low"


# ---------------------------------------------------------------------------
# Pattern C — lateral movement (both internal → ambiguous)
# ---------------------------------------------------------------------------


def test_pattern_c_lateral_movement_ambiguous():
    raw = _alert(
        src_ip="10.0.0.1",
        dest_ip="10.0.0.2",  # also internal
        category="Malware Command and Control Activity Detected",
    )
    result = assign_roles(raw, _config())
    assert result.attacker_ip is None
    assert result.victim_ip is None
    assert result.confidence == "ambiguous"


def test_pattern_c_inbound_attack_lateral_ambiguous():
    """Lateral movement: inbound-attack category but both sides are internal.

    An internal host exploiting another internal host hits the inbound_attack
    pattern but neither the external→internal nor internal→external arm fires,
    so the assigner must fall through to ambiguous (I7 coverage).
    """
    raw = _alert(
        src_ip="10.0.0.50",  # HOME_NET — attacker?
        dest_ip="10.0.0.80",  # HOME_NET — victim?
        category="Web Application Attack",
    )
    result = assign_roles(raw, _config())
    assert result.attacker_ip is None
    assert result.victim_ip is None
    assert result.confidence == "ambiguous"


def test_both_external_ambiguous():
    raw = _alert(
        src_ip="1.1.1.1",   # external
        dest_ip="8.8.8.8",  # external
        category="Malware Command and Control Activity Detected",
    )
    result = assign_roles(raw, _config())
    assert result.attacker_ip is None
    assert result.victim_ip is None
    assert result.confidence == "ambiguous"


# ---------------------------------------------------------------------------
# Pattern D — attack response (external CnC responding to internal victim)
# ---------------------------------------------------------------------------


def test_pattern_d_attack_response():
    raw = _alert(
        src_ip="185.0.0.1",  # external — CnC server sending response
        dest_ip="10.0.0.50",  # internal — compromised host (victim)
        category="Attack Response",
        signature="ET ATTACK_RESPONSE ...",
    )
    result = assign_roles(raw, _config())
    assert result.attacker_ip == "185.0.0.1"
    assert result.victim_ip == "10.0.0.50"
    assert result.confidence == "medium"


def test_pattern_d_lateral_ambiguous():
    raw = _alert(
        src_ip="10.0.0.1",
        dest_ip="10.0.0.2",
        category="Attack Response",
    )
    result = assign_roles(raw, _config())
    assert result.attacker_ip is None
    assert result.victim_ip is None
    assert result.confidence == "ambiguous"


# ---------------------------------------------------------------------------
# Scan pattern
# ---------------------------------------------------------------------------


def test_scan_pattern():
    raw = _alert(
        src_ip="198.51.100.100",
        dest_ip="10.0.0.0",
        category="Detection of a Network Scan",
    )
    result = assign_roles(raw, _config())
    assert result.attacker_ip == "198.51.100.100"
    assert result.victim_ip == "10.0.0.0"
    assert result.confidence == "medium"


# ---------------------------------------------------------------------------
# Unknown / low-signal categories
# ---------------------------------------------------------------------------


def test_unknown_category_is_ambiguous():
    raw = _alert(
        src_ip="10.0.0.1",
        dest_ip="8.8.8.8",
        category="Misc Activity",
    )
    result = assign_roles(raw, _config())
    assert result.attacker_ip is None
    assert result.victim_ip is None
    assert result.confidence in ("ambiguous", "low")


def test_policy_violation_is_low_confidence():
    raw = _alert(
        src_ip="10.0.0.1",
        dest_ip="8.8.8.8",
        category="Policy Violation",
    )
    result = assign_roles(raw, _config())
    assert result.confidence in ("ambiguous", "low")


# ---------------------------------------------------------------------------
# Initiator / responder always populated regardless of pattern
# ---------------------------------------------------------------------------


def test_initiator_responder_always_populated():
    raw = _alert(
        src_ip="10.0.0.1",
        dest_ip="8.8.8.8",
        category="Misc Activity",
    )
    result = assign_roles(raw, _config())
    assert result.initiator_ip == "10.0.0.1"
    assert result.responder_ip == "8.8.8.8"


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_missing_alert_dict_does_not_crash():
    """If the alert sub-dict is missing, assigner degrades gracefully."""
    raw = {"event_type": "alert", "src_ip": "10.0.0.1", "dest_ip": "8.8.8.8"}
    result = assign_roles(raw, _config())
    assert result.initiator_ip == "10.0.0.1"
    assert result.confidence in ("ambiguous", "low")


def test_missing_ips_do_not_crash():
    raw = {"event_type": "alert", "alert": {"category": "Misc Activity"}}
    result = assign_roles(raw, _config())
    assert result.initiator_ip == ""
    assert result.confidence in ("ambiguous", "low")


def test_attack_target_metadata_noted_in_signals():
    raw = _alert(
        src_ip="10.0.0.1",
        dest_ip="185.0.0.1",
        category="Misc Activity",
        attack_target=["Client_Endpoint"],
    )
    result = assign_roles(raw, _config())
    assert "attack_target_metadata" in result.signals_used


# ---------------------------------------------------------------------------
# Signal 2: attack_target Client_Endpoint — direction-aware assignment
# ---------------------------------------------------------------------------


def test_client_is_victim_src_external_server_dest_internal_client():
    """Regression: TLS cert / inbound-payload alerts fire with src=server, dest=client.

    ET MALWARE AsyncRAT SSL Cert and ET MALWARE Reverse Base64 MZ Header Payload
    Inbound are examples: Suricata records src_ip=C2/attacker-server, dest_ip=victim.
    The old code blindly assigned victim=src_ip, producing backwards role output.
    The fix uses HOME_NET to identify the internal client as the real victim.
    """
    raw = _alert(
        src_ip="173.232.146.62",   # external C2 server (TLS cert sender)
        dest_ip="10.2.2.37",       # internal client = victim
        category="Malware Command and Control Activity Detected",
        attack_target=["Client_Endpoint"],
    )
    result = assign_roles(raw, _config())
    assert result.attacker_ip == "173.232.146.62"
    assert result.victim_ip == "10.2.2.37"
    assert result.confidence == "medium"
    assert "attack_target_metadata" in result.signals_used


def test_client_is_victim_src_internal_client_dest_external_server():
    """Normal direction: internal client calling out to external server/C2.

    src=internal client, dest=external C2 — the pre-existing common case that
    must continue to work correctly after the fix.
    """
    raw = _alert(
        src_ip="10.0.0.1",        # internal client = victim (calling out to C2)
        dest_ip="185.220.101.45",  # external C2 server = attacker
        category="Malware Command and Control Activity Detected",
        attack_target=["Client_Endpoint"],
    )
    result = assign_roles(raw, _config())
    assert result.attacker_ip == "185.220.101.45"
    assert result.victim_ip == "10.0.0.1"
    assert result.confidence == "medium"
    assert "attack_target_metadata" in result.signals_used
