# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Deterministic source/destination role assigner (ADR-010).

Entry point: assign_roles(alert_raw, config) → RoleAssignment

Signals consulted in priority order:
  1. alert.target field  — explicit rule-author declaration; confidence=high
  2. alert.metadata.attack_target list  — corroborating signal
  3. Rule category mapping  — static CATEGORY_RULES table
  4. HOME_NET / EXTERNAL_NET membership  — applies pattern to concrete IPs
  (Signal 5 — rule direction arrow — deferred to v1 when rule text is parsed)

The assigner is a pure function: no I/O, no side effects. The triage pipeline
(weeks 5-7) calls it and writes the result into the alerts table.
"""
from __future__ import annotations

from typing import Any

from src.domain.role_assignment.models import RoleAssignment
from src.domain.role_assignment.rule_categories import detect_pattern
from src.infra.suricata_config.models import SuricataConfig

# attack_target metadata values that indicate the CLIENT/initiator is the victim.
_CLIENT_TARGET_VALUES = {"client_endpoint", "client", "endpoint"}
# attack_target metadata values that indicate the SERVER/responder is the victim.
_SERVER_TARGET_VALUES = {
    "server", "web_server", "sql_server", "dns_server", "smtp_server",
    "ftp_server", "imap_server", "pop3_server", "http_server",
}


def assign_roles(alert_raw: dict[str, Any], config: SuricataConfig) -> RoleAssignment:
    """Return a RoleAssignment for a raw EVE alert dict.

    Args:
        alert_raw: Full parsed EVE alert JSON dict (event_type must be "alert").
        config:    Parsed SuricataConfig providing HOME_NET membership checks.
    """
    src_ip: str = alert_raw.get("src_ip", "")
    dest_ip: str = alert_raw.get("dest_ip", "")
    alert: dict[str, Any] = alert_raw.get("alert") or {}
    category: str = alert.get("category", "")
    target_field: str | None = alert.get("target")  # "src_ip" | "dest_ip" | None
    metadata: dict[str, Any] = alert.get("metadata") or {}
    if isinstance(metadata, list):
        metadata = {}

    raw_attack_target = metadata.get("attack_target", [])
    attack_target_list: list[str] = (
        [raw_attack_target] if isinstance(raw_attack_target, str) else list(raw_attack_target)
    )

    src_groups = config.membership_for_ip(src_ip) if src_ip else []
    dest_groups = config.membership_for_ip(dest_ip) if dest_ip else []
    src_internal = "HOME_NET" in src_groups
    dest_internal = "HOME_NET" in dest_groups

    # ── Signal 1: target field ────────────────────────────────────────────────
    if target_field in ("src_ip", "dest_ip"):
        if target_field == "src_ip":
            victim_ip, attacker_ip = src_ip, dest_ip
        else:
            victim_ip, attacker_ip = dest_ip, src_ip
        return RoleAssignment(
            initiator_ip=src_ip,
            responder_ip=dest_ip,
            attacker_ip=attacker_ip,
            victim_ip=victim_ip,
            confidence="high",
            reasoning=(
                f"Rule defines target:{target_field} — that IP is the explicit "
                f"attack target declared by the rule author."
            ),
            signals_used=["target_field"],
        )

    # ── Accumulate signals for reasoning ─────────────────────────────────────
    signals_used: list[str] = []
    pattern, base_confidence = detect_pattern(category)
    if pattern != "unknown":
        signals_used.append("rule_category")
    if src_internal or dest_internal:
        signals_used.append("home_net_membership")
    if attack_target_list:
        signals_used.append("attack_target_metadata")

    # ── Signal 2: attack_target metadata ─────────────────────────────────────
    # ADR-010: attack_target is signal #2, before category patterns (signal #3).
    attack_target_hint = _classify_attack_target(attack_target_list)
    if attack_target_hint and (src_internal or dest_internal):
        if attack_target_hint == "client_is_victim":
            # Use HOME_NET to identify which IP is the internal client (= the actual
            # victim), not packet direction.  For TLS cert and inbound-payload alerts
            # Suricata records src=server, dest=client — the opposite of TCP-initiator
            # direction — so "src_ip == initiator" does NOT mean "src_ip == client".
            if dest_internal and not src_internal:
                # src = external server/C2 (e.g. TLS cert delivery), dest = internal client
                return RoleAssignment(
                    initiator_ip=src_ip,
                    responder_ip=dest_ip,
                    attacker_ip=src_ip,
                    victim_ip=dest_ip,
                    confidence="medium",
                    reasoning=(
                        f"Rule metadata identifies the client endpoint as the target; "
                        f"{dest_ip} (internal client) is victim, "
                        f"{src_ip} (external server) is attacker."
                    ),
                    signals_used=signals_used,
                )
            if src_internal and not dest_internal:
                # src = internal client calling out to external server/C2 (common case)
                return RoleAssignment(
                    initiator_ip=src_ip,
                    responder_ip=dest_ip,
                    attacker_ip=dest_ip,
                    victim_ip=src_ip,
                    confidence="medium",
                    reasoning=(
                        f"Rule metadata identifies the client endpoint as the target; "
                        f"{src_ip} (internal client) is victim, "
                        f"{dest_ip} (external server) is attacker."
                    ),
                    signals_used=signals_used,
                )
            # Both internal or both external — fall through to category patterns.
        if attack_target_hint == "server_is_victim":
            return RoleAssignment(
                initiator_ip=src_ip,
                responder_ip=dest_ip,
                attacker_ip=src_ip,
                victim_ip=dest_ip,
                confidence="medium",
                reasoning=(
                    f"Rule metadata identifies a server as the target; "
                    f"treating {dest_ip} (responder/server) as victim."
                ),
                signals_used=signals_used,
            )

    # ── Signals 3 + 4: category pattern + HOME_NET direction ─────────────────
    if pattern == "outbound_cnc":
        return _apply_outbound_cnc(src_ip, dest_ip, src_internal, dest_internal,
                                   category, base_confidence, signals_used)

    if pattern == "inbound_attack":
        return _apply_inbound_attack(src_ip, dest_ip, src_internal, dest_internal,
                                     category, base_confidence, signals_used)

    if pattern == "attack_response":
        return _apply_attack_response(src_ip, dest_ip, src_internal, dest_internal,
                                      category, base_confidence, signals_used)

    if pattern == "scan":
        return RoleAssignment(
            initiator_ip=src_ip,
            responder_ip=dest_ip,
            attacker_ip=src_ip,
            victim_ip=dest_ip,
            confidence=base_confidence,
            reasoning=(
                f"Category '{category}' (network scan): {src_ip} is the "
                f"scanner/attacker; {dest_ip} is being scanned."
            ),
            signals_used=signals_used,
        )

    # ── Ambiguous / insufficient signal ───────────────────────────────────────
    return _ambiguous(src_ip, dest_ip, category, signals_used)


# ── Helpers ──────────────────────────────────────────────────────────────────


def _apply_outbound_cnc(
    src_ip: str,
    dest_ip: str,
    src_internal: bool,
    dest_internal: bool,
    category: str,
    base_confidence: str,
    signals_used: list[str],
) -> RoleAssignment:
    if src_internal and not dest_internal:
        return RoleAssignment(
            initiator_ip=src_ip,
            responder_ip=dest_ip,
            attacker_ip=dest_ip,
            victim_ip=src_ip,
            confidence=base_confidence,
            reasoning=(
                f"Category '{category}' (CnC/trojan) with internal→external direction: "
                f"{src_ip} (internal host) is the compromised victim calling out to "
                f"{dest_ip} (external CnC infrastructure)."
            ),
            signals_used=signals_used,
        )
    if not src_internal and dest_internal:
        return RoleAssignment(
            initiator_ip=src_ip,
            responder_ip=dest_ip,
            attacker_ip=src_ip,
            victim_ip=dest_ip,
            confidence="low",
            reasoning=(
                f"Category '{category}' (CnC/trojan) with external→internal direction: "
                f"unusual; treating {src_ip} (external) as attacker, "
                f"{dest_ip} (internal) as victim at low confidence."
            ),
            signals_used=signals_used,
        )
    return _ambiguous(src_ip, dest_ip, category, signals_used)


def _apply_inbound_attack(
    src_ip: str,
    dest_ip: str,
    src_internal: bool,
    dest_internal: bool,
    category: str,
    base_confidence: str,
    signals_used: list[str],
) -> RoleAssignment:
    if not src_internal and dest_internal:
        return RoleAssignment(
            initiator_ip=src_ip,
            responder_ip=dest_ip,
            attacker_ip=src_ip,
            victim_ip=dest_ip,
            confidence=base_confidence,
            reasoning=(
                f"Category '{category}' (inbound attack) with external→internal direction: "
                f"{src_ip} (external) is the attacker; {dest_ip} (internal) is the victim."
            ),
            signals_used=signals_used,
        )
    if src_internal and not dest_internal:
        return RoleAssignment(
            initiator_ip=src_ip,
            responder_ip=dest_ip,
            attacker_ip=src_ip,
            victim_ip=dest_ip,
            confidence="low",
            reasoning=(
                f"Category '{category}' (inbound attack) but internal→external direction: "
                f"treating {src_ip} (internal) as attacker, {dest_ip} as victim at low confidence."
            ),
            signals_used=signals_used,
        )
    return _ambiguous(src_ip, dest_ip, category, signals_used)


def _apply_attack_response(
    src_ip: str,
    dest_ip: str,
    src_internal: bool,
    dest_internal: bool,
    category: str,
    base_confidence: str,
    signals_used: list[str],
) -> RoleAssignment:
    if not src_internal and dest_internal:
        return RoleAssignment(
            initiator_ip=src_ip,
            responder_ip=dest_ip,
            attacker_ip=src_ip,
            victim_ip=dest_ip,
            confidence=base_confidence,
            reasoning=(
                f"Category '{category}' (attack response): {src_ip} (external) is "
                f"the CnC server responding to the compromised {dest_ip} (internal)."
            ),
            signals_used=signals_used,
        )
    return _ambiguous(src_ip, dest_ip, category, signals_used)


def _classify_attack_target(attack_target_list: list[str]) -> str | None:
    """Return 'client_is_victim', 'server_is_victim', or None."""
    for val in attack_target_list:
        norm = val.lower()
        if norm in _CLIENT_TARGET_VALUES:
            return "client_is_victim"
        if norm in _SERVER_TARGET_VALUES:
            return "server_is_victim"
    return None


def _ambiguous(
    src_ip: str,
    dest_ip: str,
    category: str,
    signals_used: list[str],
) -> RoleAssignment:
    return RoleAssignment(
        initiator_ip=src_ip,
        responder_ip=dest_ip,
        attacker_ip=None,
        victim_ip=None,
        confidence="ambiguous",
        reasoning=(
            f"Category '{category}' with current network context provides "
            f"insufficient role-assignment signal. The LLM should reason from "
            f"flow context and enrichment."
        ),
        signals_used=signals_used,
    )
