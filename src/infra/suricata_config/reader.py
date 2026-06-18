# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Main entry point for reading suricata.yaml into a SuricataConfig."""
from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime
from pathlib import Path

from src.errors import SuricataConfigInvalid, SuricataConfigMissing
from src.infra.suricata_config.models import RuleFileSummary, SuricataConfig
from src.infra.suricata_config.parser import (
    ParseError,
    extract_address_groups,
    extract_rule_file_paths,
    load_yaml_with_includes,
)
from src.infra.suricata_config.validator import validate_home_net

_DEFAULT_CONFIG_PATH = "/host/suricata/config/suricata.yaml"

_SERVER_GROUP_NAMES = {
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


def read_config(config_path: str | None = None) -> SuricataConfig:
    """Read and parse suricata.yaml, returning a validated SuricataConfig.

    Raises:
        SuricataConfigMissing: if the file does not exist or is not readable.
        SuricataConfigInvalid: if YAML is malformed or HOME_NET is absent.
    """
    path_str = config_path or os.environ.get("VX_SURICATA_CONFIG_PATH", _DEFAULT_CONFIG_PATH)
    path = Path(path_str)

    if not path.exists():
        raise SuricataConfigMissing(
            "suricata.yaml not found at configured path",
            detail=path_str,
        )

    if not path.is_file():
        raise SuricataConfigMissing(
            "configured path is not a file",
            detail=path_str,
        )

    try:
        raw_bytes = path.read_bytes()
        raw_hash = hashlib.sha256(raw_bytes).hexdigest()
    except OSError as e:
        raise SuricataConfigMissing(
            "cannot read suricata.yaml",
            detail=f"{path_str}: {e}",
            cause=e,
        ) from e

    try:
        data, paths_read = load_yaml_with_includes(path)
    except ParseError as e:
        raise SuricataConfigInvalid(str(e), detail=path_str, cause=e) from e

    try:
        address_cidrs, port_groups = extract_address_groups(data)
    except Exception as e:
        raise SuricataConfigInvalid(
            f"failed to extract address groups: {e}", detail=path_str, cause=e
        ) from e

    validate_home_net(address_cidrs, path_str)

    home_net = address_cidrs.get("HOME_NET", [])
    external_net = address_cidrs.get("EXTERNAL_NET", [])

    server_groups = {
        name: nets
        for name, nets in address_cidrs.items()
        if name in _SERVER_GROUP_NAMES
    }

    # Also include any customer-defined groups not in our known set
    known = {"HOME_NET", "EXTERNAL_NET"} | _SERVER_GROUP_NAMES
    for name, nets in address_cidrs.items():
        if name not in known:
            server_groups[name] = nets

    rule_file_paths = extract_rule_file_paths(data)
    rule_file_summaries = _summarise_rule_files(rule_file_paths, path.parent)

    return SuricataConfig(
        home_net=home_net,
        external_net=external_net,
        server_groups=server_groups,
        port_groups=port_groups,
        rule_file_paths=rule_file_paths,
        rule_file_summaries=rule_file_summaries,
        config_file_paths_read=paths_read,
        read_at=datetime.now(tz=UTC),
        raw_yaml_hash=raw_hash,
    )


def _summarise_rule_files(
    rule_file_paths: list[str], config_dir: Path
) -> dict[str, RuleFileSummary]:
    summaries: dict[str, RuleFileSummary] = {}
    for rp in rule_file_paths:
        p = (config_dir / rp).resolve()
        if p.exists() and p.is_file():
            stat = p.stat()
            try:
                line_count = sum(1 for _ in p.open(encoding="utf-8", errors="replace"))
            except OSError:
                line_count = None
            summaries[rp] = RuleFileSummary(
                path=str(p),
                exists=True,
                line_count=line_count,
                mtime=stat.st_mtime,
            )
        else:
            summaries[rp] = RuleFileSummary(
                path=str(p), exists=False, line_count=None, mtime=None
            )
    return summaries
