# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""SuricataConfig dataclass — the structured output of parsing suricata.yaml."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime


@dataclass
class RuleFileSummary:
    path: str
    exists: bool
    line_count: int | None
    mtime: float | None


@dataclass
class SuricataConfig:
    """Structured representation of a parsed suricata.yaml."""

    home_net: list[ipaddress.IPv4Network | ipaddress.IPv6Network]
    external_net: list[ipaddress.IPv4Network | ipaddress.IPv6Network]
    server_groups: dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]]
    port_groups: dict[str, str]
    rule_file_paths: list[str]
    rule_file_summaries: dict[str, RuleFileSummary]
    config_file_paths_read: list[str]
    read_at: datetime
    raw_yaml_hash: str

    def membership_for_ip(self, ip: str) -> list[str]:
        """Return list of group names this IP belongs to (HOME_NET, HTTP_SERVERS, etc.)."""
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return []

        memberships: list[str] = []

        if any(addr in net for net in self.home_net):
            memberships.append("HOME_NET")
        else:
            memberships.append("EXTERNAL_NET")

        for group_name, networks in self.server_groups.items():
            if any(addr in net for net in networks):
                memberships.append(group_name)

        return memberships

    def to_prompt_context(self) -> str:
        """Render network group definitions for injection into LLM prompts."""
        lines = ["## Suricata Network Configuration"]

        lines.append(
            f"HOME_NET: {', '.join(str(n) for n in self.home_net) or '(not set)'}"
        )
        lines.append(
            f"EXTERNAL_NET: {', '.join(str(n) for n in self.external_net) or 'any (not $HOME_NET)'}"
        )

        if self.server_groups:
            lines.append("\nServer groups:")
            for name, networks in sorted(self.server_groups.items()):
                nets_str = ", ".join(str(n) for n in networks) if networks else "any"
                lines.append(f"  {name}: {nets_str}")

        lines.append(f"\nConfig read at: {self.read_at.isoformat()}")
        return "\n".join(lines)
