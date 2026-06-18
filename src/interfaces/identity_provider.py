# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""IdentityProvider interface — abstract over IP-to-identity resolution.

Concrete implementations:
  v0.1  src/identity/reverse_dns/provider.py  — hostname via stdlib reverse DNS
  v1    Active Directory via LDAPS (read-only service account)
  v1.x  Entra ID, Okta, Google Workspace

Application code must import this Protocol, never the concrete class.
Concrete instances arrive via dependency injection.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from src.identity.models import IdentityFacts


@runtime_checkable
class IdentityProvider(Protocol):
    """Resolve an IP address to identity and hostname context."""

    async def resolve_ip(self, ip: str) -> IdentityFacts | None:
        """Return identity facts for an IP, or None if not applicable.

        Returns:
            None — provider explicitly does not handle this IP (e.g. external
                   IPs for the reverse DNS provider). Ledger shows "not applicable".
            IdentityFacts(hostname=None) — provider attempted a lookup but failed
                   (NXDOMAIN, timeout, DNS unreachable). Ledger shows "failing".
            IdentityFacts(hostname=<str>) — successful resolution.
        """
        ...
