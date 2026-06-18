# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Opaque installation identifier.

A random UUID generated once at first EULA accept and stored in system_config.
It is not linked to any user, IP address, or alert content — its only purpose
is to correlate telemetry submissions from the same installation over time
(e.g., "agreement rate went from 0.87 to 0.94 after a prompt update").
"""
from __future__ import annotations

import uuid

_SYSTEM_CONFIG_KEY = "install_id"


async def ensure_install_id(op_store) -> str:
    """Return the existing install UUID, creating it if this is the first call."""
    existing = await op_store.get_config(_SYSTEM_CONFIG_KEY)
    if existing:
        return existing
    new_id = str(uuid.uuid4())
    await op_store.set_config(_SYSTEM_CONFIG_KEY, new_id)
    return new_id


async def get_install_id(op_store) -> str | None:
    """Return the install UUID, or None if not yet created."""
    return await op_store.get_config(_SYSTEM_CONFIG_KEY)
