# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Validate parsed SuricataConfig fields; raise on fatal missing data."""
from __future__ import annotations

import ipaddress

from src.errors import SuricataConfigInvalid


def validate_home_net(
    address_cidrs: dict[str, list[ipaddress.IPv4Network | ipaddress.IPv6Network]],
    config_path: str,
) -> None:
    """Raise SuricataConfigInvalid if HOME_NET is absent or empty after parsing."""
    if "HOME_NET" not in address_cidrs:
        raise SuricataConfigInvalid(
            "HOME_NET is not defined in vars.address-groups",
            detail=config_path,
        )
    if not address_cidrs["HOME_NET"]:
        raise SuricataConfigInvalid(
            "HOME_NET resolved to an empty network list "
            "(value is 'any', all negations, or unparseable CIDRs)",
            detail=config_path,
        )
