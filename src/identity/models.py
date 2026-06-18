# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Identity models — uniform return type for all IdentityProvider implementations."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass
class IdentityFacts:
    """Identity and hostname context for a single IP address.

    v0.1 (ReverseDNSIdentityProvider): hostname only; username, ou_path, and
    group_memberships are always None / empty.  v1 Active Directory fills these.
    Role assigner and prompt builder consume hostname regardless of source.
    """

    ip: str
    hostname: str | None          # PTR record in v0.1; AD ComputerName in v1
    username: str | None          # always None in v0.1; AD SAMAccountName in v1
    ou_path: str | None           # always None in v0.1
    group_memberships: list[str]  # always [] in v0.1
    source: str                   # "reverse_dns" in v0.1, "active_directory" in v1
    queried_at: datetime = field(default_factory=lambda: datetime.now(UTC))
