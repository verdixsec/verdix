# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Parse suricata.yaml into raw dicts, resolving includes and variables."""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any

import yaml

_MAX_INCLUDE_DEPTH = 5
_MAX_VAR_EXPANSION_PASSES = 10

# Known address-group variable names in suricata.yaml
_ADDRESS_GROUPS = {
    "HOME_NET",
    "EXTERNAL_NET",
    "HTTP_SERVERS",
    "SMTP_SERVERS",
    "SQL_SERVERS",
    "DNS_SERVERS",
    "TELNET_SERVERS",
    "AIM_SERVERS",
    "DC_SERVERS",
    "DNP3_SERVER",
    "DNP3_CLIENT",
    "MODBUS_CLIENT",
    "MODBUS_SERVER",
    "ENIP_CLIENT",
    "ENIP_SERVER",
}


class ParseError(Exception):
    """Internal parse failure — caller converts to SuricataConfigInvalid."""


def load_yaml_with_includes(
    config_path: Path, depth: int = 0
) -> tuple[dict[str, Any], list[str]]:
    """Load YAML file, recursively resolving include: directives.

    Returns (merged_dict, list_of_all_file_paths_read).
    Raises ParseError on YAML syntax errors or depth limit exceeded.
    """
    if depth > _MAX_INCLUDE_DEPTH:
        raise ParseError(
            f"include: depth limit ({_MAX_INCLUDE_DEPTH}) exceeded at {config_path}"
        )

    try:
        raw = config_path.read_text(encoding="utf-8")
    except OSError as e:
        raise ParseError(f"cannot read {config_path}: {e}") from e

    try:
        data: dict[str, Any] = yaml.safe_load(raw) or {}
    except yaml.YAMLError as e:
        raise ParseError(f"YAML parse error in {config_path}: {e}") from e

    if not isinstance(data, dict):
        raise ParseError(f"{config_path} does not contain a YAML mapping at root")

    paths_read = [str(config_path)]

    includes = data.pop("include", None)
    if includes:
        if isinstance(includes, str):
            includes = [includes]
        for inc in includes:
            inc_path = (config_path.parent / inc).resolve()
            inc_data, inc_paths = load_yaml_with_includes(inc_path, depth + 1)
            paths_read.extend(inc_paths)
            _deep_merge(data, inc_data)

    return data, paths_read


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> None:
    """Merge override into base in-place; override wins on conflicts."""
    for key, val in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(val, dict):
            _deep_merge(base[key], val)
        else:
            base[key] = val


def extract_address_groups(
    data: dict[str, Any],
) -> tuple[
    dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]],
    dict[str, str],
]:
    """Extract vars.address-groups and vars.port-groups from raw YAML dict.

    Returns (address_group_cidrs, port_group_raw_strings).
    """
    vars_block: dict[str, Any] = data.get("vars", {}) or {}
    raw_addr: dict[str, Any] = vars_block.get("address-groups", {}) or {}
    raw_port: dict[str, Any] = vars_block.get("port-groups", {}) or {}

    # Resolve variable references iteratively (variables can reference each other)
    resolved_strings = _resolve_variable_references(
        {k: str(v) for k, v in raw_addr.items()}
    )

    address_cidrs: dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]] = {}
    for name, value in resolved_strings.items():
        address_cidrs[name] = _parse_address_value(value, name)

    port_groups = {k: str(v) for k, v in raw_port.items()}
    return address_cidrs, port_groups


def _resolve_variable_references(
    raw: dict[str, str],
) -> dict[str, str]:
    """Expand $VAR references within address-group values, handling !$VAR negation.

    Suricata supports:
      EXTERNAL_NET: "!$HOME_NET"
      HTTP_SERVERS: "$HOME_NET"
      SOME_GROUP: "[$HOME_NET, 10.0.0.0/8]"

    We expand these to concrete CIDR strings for parsing. Negation (!$VAR) is
    preserved as a prefix on each expanded entry so the caller can filter them.
    """
    resolved = dict(raw)

    for _ in range(_MAX_VAR_EXPANSION_PASSES):
        changed = False
        for name, value in resolved.items():
            new_value = _expand_vars_in_string(value, resolved)
            if new_value != value:
                resolved[name] = new_value
                changed = True
        if not changed:
            break

    return resolved


def _expand_vars_in_string(value: str, vars_: dict[str, str]) -> str:
    """Replace $VAR_NAME tokens in value with their resolved strings.

    Handles !$VAR negation by applying ! to every element in the expanded list,
    so !$HOME_NET where HOME_NET=[10.0.0.0/8, 192.168.0.0/16] becomes
    !10.0.0.0/8, !192.168.0.0/16.
    """

    def replacer(m: re.Match[str]) -> str:
        negate = m.group(1)  # "!" or ""
        var_name = m.group(2)
        if var_name not in vars_:
            return m.group(0)  # leave unexpanded if unknown
        replacement = vars_[var_name].strip()
        if replacement.startswith("[") and replacement.endswith("]"):
            replacement = replacement[1:-1]
        if negate:
            entries = [e.strip() for e in replacement.split(",") if e.strip()]
            return ", ".join(f"!{e}" for e in entries)
        return replacement

    return re.sub(r"(!?)\$([A-Z0-9_]+)", replacer, value)


def _parse_address_value(
    value: str, name: str
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse a (possibly list) Suricata address value into CIDR objects.

    Special values:
      "any"       → empty list (means all addresses; caller treats absence as any)
      "!$HOME_NET" after expansion → negation, ignored (we model positive membership only)
    """
    value = value.strip()

    if value.lower() == "any":
        return []

    # Remove outer brackets: [10.0.0.0/8, 192.168.0.0/16]
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]

    entries = [e.strip() for e in value.split(",") if e.strip()]
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []

    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue
        # Skip negations — we model positive set membership only
        if entry.startswith("!"):
            continue
        # Skip any remaining unexpanded variable references
        if entry.startswith("$"):
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            # Non-fatal: log-worthy but don't crash on a single bad entry
            pass

    return networks


def extract_rule_file_paths(data: dict[str, Any]) -> list[str]:
    """Extract rule file paths declared under rule-files: key."""
    rule_files = data.get("rule-files", []) or []
    if isinstance(rule_files, str):
        rule_files = [rule_files]
    return [str(r) for r in rule_files if r]
