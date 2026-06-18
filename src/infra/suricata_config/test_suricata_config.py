# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Tests for the suricata.yaml reader, parser, and models."""
from __future__ import annotations

import ipaddress
import textwrap
from pathlib import Path

import pytest

from src.errors import SuricataConfigInvalid, SuricataConfigMissing
from src.infra.suricata_config.parser import (
    _parse_address_value,
    _resolve_variable_references,
    extract_address_groups,
    load_yaml_with_includes,
)
from src.infra.suricata_config.reader import read_config

_FIXTURES = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# _parse_address_value
# ---------------------------------------------------------------------------


def test_parse_single_cidr() -> None:
    result = _parse_address_value("192.168.0.0/16", "HOME_NET")
    assert result == [ipaddress.ip_network("192.168.0.0/16")]


def test_parse_bracket_list() -> None:
    result = _parse_address_value("[10.0.0.0/8, 172.16.0.0/12]", "HOME_NET")
    assert ipaddress.ip_network("10.0.0.0/8") in result
    assert ipaddress.ip_network("172.16.0.0/12") in result


def test_parse_any_returns_empty() -> None:
    assert _parse_address_value("any", "AIM_SERVERS") == []


def test_parse_negation_skipped() -> None:
    # !$HOME_NET after expansion may appear as negated entries — must not crash
    result = _parse_address_value("!192.168.0.0/16", "EXTERNAL_NET")
    assert result == []


def test_parse_unexpanded_var_skipped() -> None:
    result = _parse_address_value("$UNKNOWN_VAR", "TEST")
    assert result == []


def test_parse_invalid_cidr_skipped() -> None:
    # A bad CIDR in a list should not crash; bad entry is skipped
    result = _parse_address_value("[10.0.0.0/8, not-a-cidr]", "HOME_NET")
    assert result == [ipaddress.ip_network("10.0.0.0/8")]


# ---------------------------------------------------------------------------
# _resolve_variable_references
# ---------------------------------------------------------------------------


def test_resolve_simple_reference() -> None:
    raw = {"HOME_NET": "10.0.0.0/8", "HTTP_SERVERS": "$HOME_NET"}
    resolved = _resolve_variable_references(raw)
    assert resolved["HTTP_SERVERS"] == "10.0.0.0/8"


def test_resolve_negation_preserved() -> None:
    raw = {"HOME_NET": "10.0.0.0/8", "EXTERNAL_NET": "!$HOME_NET"}
    resolved = _resolve_variable_references(raw)
    assert "!10.0.0.0/8" in resolved["EXTERNAL_NET"]


def test_resolve_list_splicing() -> None:
    raw = {
        "HOME_NET": "[10.0.0.0/8, 192.168.0.0/16]",
        "HTTP_SERVERS": "$HOME_NET",
    }
    resolved = _resolve_variable_references(raw)
    assert "10.0.0.0/8" in resolved["HTTP_SERVERS"]
    assert "192.168.0.0/16" in resolved["HTTP_SERVERS"]


def test_resolve_unknown_var_left_as_is() -> None:
    raw = {"HTTP_SERVERS": "$UNKNOWN_GROUP"}
    resolved = _resolve_variable_references(raw)
    assert "$UNKNOWN_GROUP" in resolved["HTTP_SERVERS"]


# ---------------------------------------------------------------------------
# extract_address_groups
# ---------------------------------------------------------------------------


def test_extract_address_groups_basic() -> None:
    data = {
        "vars": {
            "address-groups": {
                "HOME_NET": "[192.168.0.0/16, 10.0.0.0/8]",
                "EXTERNAL_NET": "!$HOME_NET",
                "DNS_SERVERS": "192.168.1.1",
            },
            "port-groups": {"HTTP_PORTS": "80"},
        }
    }
    cidrs, ports = extract_address_groups(data)
    assert ipaddress.ip_network("192.168.0.0/16") in cidrs["HOME_NET"]
    assert ipaddress.ip_network("10.0.0.0/8") in cidrs["HOME_NET"]
    assert cidrs["EXTERNAL_NET"] == []  # all negations → empty positive set
    assert ipaddress.ip_network("192.168.1.1/32") in cidrs["DNS_SERVERS"]
    assert ports["HTTP_PORTS"] == "80"


def test_extract_missing_vars_block() -> None:
    cidrs, ports = extract_address_groups({})
    assert cidrs == {}
    assert ports == {}


# ---------------------------------------------------------------------------
# load_yaml_with_includes
# ---------------------------------------------------------------------------


def test_load_simple_yaml(tmp_path: Path) -> None:
    f = tmp_path / "suricata.yaml"
    f.write_text("vars:\n  address-groups:\n    HOME_NET: '10.0.0.0/8'\n")
    data, paths = load_yaml_with_includes(f)
    assert data["vars"]["address-groups"]["HOME_NET"] == "10.0.0.0/8"
    assert str(f) in paths


def test_load_with_include(tmp_path: Path) -> None:
    inc = tmp_path / "vars.yaml"
    inc.write_text("vars:\n  address-groups:\n    HOME_NET: '10.0.0.0/8'\n")
    main = tmp_path / "suricata.yaml"
    main.write_text("include: vars.yaml\nrule-files:\n  - local.rules\n")
    data, paths = load_yaml_with_includes(main)
    assert data["vars"]["address-groups"]["HOME_NET"] == "10.0.0.0/8"
    assert "rule-files" in data
    assert len(paths) == 2


def test_load_include_depth_limit(tmp_path: Path) -> None:
    # Create a chain of 7 includes — exceeds the limit of 5
    prev = tmp_path / "level6.yaml"
    prev.write_text("vars:\n  address-groups:\n    HOME_NET: '10.0.0.0/8'\n")
    for i in range(5, 0, -1):
        current = tmp_path / f"level{i}.yaml"
        current.write_text(f"include: level{i+1}.yaml\n")
    root = tmp_path / "suricata.yaml"
    root.write_text("include: level1.yaml\n")

    from src.infra.suricata_config.parser import ParseError

    with pytest.raises(ParseError, match="depth limit"):
        load_yaml_with_includes(root)


def test_load_malformed_yaml(tmp_path: Path) -> None:
    f = tmp_path / "suricata.yaml"
    f.write_text("vars: {unclosed: [bracket\n")

    from src.infra.suricata_config.parser import ParseError

    with pytest.raises(ParseError, match="YAML parse error"):
        load_yaml_with_includes(f)


def test_load_non_mapping_root(tmp_path: Path) -> None:
    f = tmp_path / "suricata.yaml"
    f.write_text("- item1\n- item2\n")

    from src.infra.suricata_config.parser import ParseError

    with pytest.raises(ParseError, match="does not contain a YAML mapping"):
        load_yaml_with_includes(f)


# ---------------------------------------------------------------------------
# read_config — integration against fixtures
# ---------------------------------------------------------------------------


def test_read_config_reference_fixture() -> None:
    cfg = read_config(str(_FIXTURES / "reference.yaml"))
    assert ipaddress.ip_network("192.168.0.0/16") in cfg.home_net
    assert ipaddress.ip_network("10.0.0.0/8") in cfg.home_net
    assert ipaddress.ip_network("172.16.0.0/12") in cfg.home_net
    assert cfg.external_net == []  # "!$HOME_NET" → all negations → empty positive
    assert ipaddress.ip_network("192.168.1.1/32") in cfg.server_groups["DNS_SERVERS"]
    assert len(cfg.rule_file_paths) == 2
    assert cfg.raw_yaml_hash != ""


def test_read_config_with_include_fixture() -> None:
    cfg = read_config(str(_FIXTURES / "with_include_main.yaml"))
    assert ipaddress.ip_network("10.10.0.0/16") in cfg.home_net
    assert ipaddress.ip_network("10.20.0.0/16") in cfg.home_net
    assert len(cfg.config_file_paths_read) == 2


def test_read_config_missing_file() -> None:
    with pytest.raises(SuricataConfigMissing):
        read_config("/nonexistent/path/suricata.yaml")


def test_read_config_malformed_yaml(tmp_path: Path) -> None:
    f = tmp_path / "suricata.yaml"
    f.write_text("vars: {unclosed: [bracket\n")
    with pytest.raises(SuricataConfigInvalid):
        read_config(str(f))


def test_read_config_missing_home_net(tmp_path: Path) -> None:
    f = tmp_path / "suricata.yaml"
    f.write_text(
        textwrap.dedent("""\
        vars:
          address-groups:
            EXTERNAL_NET: "!$HOME_NET"
        """)
    )
    with pytest.raises(SuricataConfigInvalid, match="HOME_NET"):
        read_config(str(f))


def test_read_config_home_net_any_fails(tmp_path: Path) -> None:
    # HOME_NET: any resolves to empty CIDR list → must fail fast
    f = tmp_path / "suricata.yaml"
    f.write_text("vars:\n  address-groups:\n    HOME_NET: any\n")
    with pytest.raises(SuricataConfigInvalid, match="HOME_NET"):
        read_config(str(f))


# ---------------------------------------------------------------------------
# SuricataConfig.membership_for_ip
# ---------------------------------------------------------------------------


def test_membership_for_ip_home_net() -> None:
    cfg = read_config(str(_FIXTURES / "reference.yaml"))
    memberships = cfg.membership_for_ip("192.168.1.50")
    assert "HOME_NET" in memberships
    assert "EXTERNAL_NET" not in memberships


def test_membership_for_ip_external() -> None:
    cfg = read_config(str(_FIXTURES / "reference.yaml"))
    memberships = cfg.membership_for_ip("8.8.8.8")
    assert "EXTERNAL_NET" in memberships
    assert "HOME_NET" not in memberships


def test_membership_for_ip_server_group() -> None:
    cfg = read_config(str(_FIXTURES / "reference.yaml"))
    # DNS_SERVERS is [192.168.1.1, 192.168.1.2] in the fixture
    memberships = cfg.membership_for_ip("192.168.1.1")
    assert "DNS_SERVERS" in memberships
    assert "HOME_NET" in memberships


def test_membership_for_invalid_ip() -> None:
    cfg = read_config(str(_FIXTURES / "reference.yaml"))
    assert cfg.membership_for_ip("not-an-ip") == []


# ---------------------------------------------------------------------------
# SuricataConfig.to_prompt_context
# ---------------------------------------------------------------------------


def test_to_prompt_context_contains_home_net() -> None:
    cfg = read_config(str(_FIXTURES / "reference.yaml"))
    ctx = cfg.to_prompt_context()
    assert "HOME_NET" in ctx
    assert "192.168.0.0/16" in ctx


def test_to_prompt_context_contains_server_groups() -> None:
    cfg = read_config(str(_FIXTURES / "reference.yaml"))
    ctx = cfg.to_prompt_context()
    assert "DNS_SERVERS" in ctx
