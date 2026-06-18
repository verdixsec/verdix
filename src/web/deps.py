# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Dependency registry for the web layer.

Stores are configured once at application startup (from src/main.py) and
retrieved by route handlers via the get_*() accessors. This avoids threading
stores through FastAPI's DI system for every route.

License-accepted state is cached in memory after the first DB read. Once set
to True it never reverts — no locking needed.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.infra.db.disposition_store import SQLiteDispositionStore
    from src.infra.db.event_store import SQLiteEventStore
    from src.infra.db.operational_store import SQLiteOperationalStore

_event_store: "SQLiteEventStore | None" = None
_operational_store: "SQLiteOperationalStore | None" = None
_disposition_store: "SQLiteDispositionStore | None" = None

# Cached after first DB read; True once EULA accepted, never reverts.
_license_accepted: bool | None = None


def configure_stores(
    event: "SQLiteEventStore",
    operational: "SQLiteOperationalStore",
    disposition: "SQLiteDispositionStore",
) -> None:
    global _event_store, _operational_store, _disposition_store
    _event_store = event
    _operational_store = operational
    _disposition_store = disposition


def get_event_store() -> "SQLiteEventStore":
    if _event_store is None:
        raise RuntimeError("Stores not configured — call configure_stores() at startup")
    return _event_store


def get_operational_store() -> "SQLiteOperationalStore":
    if _operational_store is None:
        raise RuntimeError("Stores not configured — call configure_stores() at startup")
    return _operational_store


def get_disposition_store() -> "SQLiteDispositionStore":
    if _disposition_store is None:
        raise RuntimeError("Stores not configured — call configure_stores() at startup")
    return _disposition_store


async def check_license_accepted() -> bool:
    global _license_accepted
    if _license_accepted is not None:
        return _license_accepted
    try:
        store = get_operational_store()
        val = await store.get_config("eula_accepted")
        _license_accepted = val == "true"
    except Exception:  # noqa: BLE001
        _license_accepted = False
    return _license_accepted


def mark_license_accepted() -> None:
    global _license_accepted
    _license_accepted = True
