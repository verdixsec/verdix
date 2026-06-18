# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""VT fixture loader for the eval harness.

Provides a fixture_loader callable compatible with VirusTotalClient's
fixture_loader constructor argument. The loader reads responses.json and
returns the matching VT API response dict for a given (type, value) pair,
or None if the indicator is not in fixtures (simulates a 404 from VT).

Usage (in eval pipeline):
    from eval.fixtures.virustotal.loader import make_vt_fixture_loader
    from src.enrichment.virustotal.client import VirusTotalClient
    from src.infra.cache.memory import InMemoryTTLCache

    vt_client = VirusTotalClient(
        InMemoryTTLCache(),
        api_key="",
        fixture_loader=make_vt_fixture_loader(),
    )
"""
from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

_FIXTURE_FILE = Path(__file__).parent / "responses.json"


def make_vt_fixture_loader() -> Callable[[str, str], dict | None]:
    """Return a fixture_loader that reads from responses.json.

    The returned callable matches the VirusTotalClient fixture_loader signature:
      loader(indicator_type: str, indicator_value: str) -> dict | None

    Returns the matching VT API response dict, or None if not in fixtures.
    """
    with _FIXTURE_FILE.open(encoding="utf-8") as fh:
        fixtures: dict[str, dict] = json.load(fh)

    # Strip metadata keys that start with "_".
    responses = {k: v for k, v in fixtures.items() if not k.startswith("_")}

    def loader(indicator_type: str, indicator_value: str) -> dict | None:
        key = f"{indicator_type}:{indicator_value}"
        return responses.get(key)

    return loader
