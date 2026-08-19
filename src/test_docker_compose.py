# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Structural checks on the app service's container healthcheck (ADR-019
Stage 2). Guards against silent regression of the interval/timeout/retries/
start_period values, the healthcheck's own exec-vs-shell form, and the
restart policy — without needing Docker itself.
"""
from __future__ import annotations

import pathlib

import yaml

_ROOT = pathlib.Path(__file__).resolve().parent.parent
# docker-compose.fat.yml was retired (ADR-020, fat-image deployment path
# retired) — only the lean compose file exists now.
_COMPOSE_FILES = ["docker-compose.yml"]


def _load(name: str) -> dict:
    with (_ROOT / name).open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def test_app_healthcheck_present_with_expected_values() -> None:
    for name in _COMPOSE_FILES:
        doc = _load(name)
        hc = doc["services"]["app"].get("healthcheck")
        assert hc is not None, f"{name}: app service has no healthcheck"
        assert hc["interval"] == "30s"
        assert hc["timeout"] == "5s"
        assert hc["retries"] == 3
        assert hc["start_period"] == "60s"


def test_app_healthcheck_polls_the_health_route_without_curl() -> None:
    for name in _COMPOSE_FILES:
        doc = _load(name)
        test_cmd = doc["services"]["app"]["healthcheck"]["test"]
        assert test_cmd[0] == "CMD"  # exec form — no shell needed for a plain GET
        joined = " ".join(test_cmd)
        assert "/health" in joined
        assert "curl" not in joined.lower()  # not installed in the app image


def test_app_healthcheck_script_is_valid_python() -> None:
    """Compiles the exact script the container will run — catches a typo or
    a bad YAML escape before it ships as a container that reports unhealthy
    forever."""
    for name in _COMPOSE_FILES:
        doc = _load(name)
        test_cmd = doc["services"]["app"]["healthcheck"]["test"]
        script = test_cmd[test_cmd.index("-c") + 1]
        compile(script, f"<{name} healthcheck>", "exec")


def test_restart_policy_unchanged_on_both_services() -> None:
    for name in _COMPOSE_FILES:
        doc = _load(name)
        assert doc["services"]["app"]["restart"] == "unless-stopped"
        assert doc["services"]["llm"]["restart"] == "unless-stopped"
