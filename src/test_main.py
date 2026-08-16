# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Tests for the lifespan's startup-blocked path (ADR-019 verification defect 1).

On-box verification against real NFS found that a blocked startup (eve.json
unreadable, suricata.yaml readable) still logged `ingestion_active: true` and
still constructed and started EvePipeline/TriageWorker — which then died
within a millisecond and logged eve_indexer_stopped/alert_dispatcher_stopped,
reproducing the exact log signature the 2026-08-12 incident (and this ADR)
exists to eliminate. These tests exercise the real lifespan end to end
(real DB, real store wiring) rather than mocking `_build_lifespan`'s
internals, since the defect was in the interaction between `suricata_config`
and `blocking_reasons`, not in either alone.
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
from fastapi import FastAPI
from structlog.testing import capture_logs

from src.infra.db.session import close_db
from src.main import _build_lifespan

_FIXTURES = Path(__file__).resolve().parent / "infra" / "suricata_config" / "fixtures"
_REFERENCE_YAML = _FIXTURES / "reference.yaml"


@pytest.fixture(autouse=True)
async def _fresh_db() -> AsyncIterator[None]:
    await close_db()  # defensive: dispose any engine left by a previous test
    yield
    await close_db()


def _cfg(tmp_path: Path, *, eve_log_path: str, suricata_config_path: str) -> dict:
    return {
        "db_path": str(tmp_path / "test.db"),
        "cache_db_path": str(tmp_path / "test-cache.db"),
        "eve_log_path": eve_log_path,
        "suricata_config_path": suricata_config_path,
        "poll_interval_ms": 500,
        "context_delay_s": 30.0,
        "daily_cap": 300,
        "retention_days": 7,
        "ollama_url": "http://llm:11434/api/chat",
        "ollama_model": "gemma4:e4b-it-q8_0",
        "ollama_timeout": 600.0,
        "geoip_country_db": str(tmp_path / "missing-country.mmdb"),
        "geoip_asn_db": str(tmp_path / "missing-asn.mmdb"),
        "vt_api_key": None,
    }


async def test_blocked_startup_reports_ingestion_active_false(tmp_path: Path) -> None:
    """eve.json unreadable, suricata.yaml readable — defect 1a."""
    cfg = _cfg(
        tmp_path,
        eve_log_path=str(tmp_path / "missing-eve.json"),
        suricata_config_path=str(_REFERENCE_YAML),
    )
    app = FastAPI()

    with capture_logs() as logs:
        async with _build_lifespan(cfg)(app):
            pass

    started = next(e for e in logs if e["event"] == "verdix_started")
    assert started["ingestion_active"] is False
    assert app.state.ingestion_status.blocked_reason is not None


async def test_blocked_startup_does_not_create_pipeline_or_worker_tasks(
    tmp_path: Path,
) -> None:
    """Defect 1b: a blocked startup must not construct/start EvePipeline or
    TriageWorker at all — starting them and letting the tailer fail
    immediately reproduces the eve_indexer_stopped/alert_dispatcher_stopped
    signature this ADR exists to eliminate. eve_cleanup is unaffected by the
    block and must still start."""
    cfg = _cfg(
        tmp_path,
        eve_log_path=str(tmp_path / "missing-eve.json"),
        suricata_config_path=str(_REFERENCE_YAML),
    )
    app = FastAPI()

    with capture_logs() as logs:
        async with _build_lifespan(cfg)(app):
            pass

    started = next(e for e in logs if e["event"] == "verdix_started")
    assert started["tasks"] == ["eve_cleanup"]

    events = [e["event"] for e in logs]
    assert "eve_pipeline_started" not in events
    assert "eve_tailer_started" not in events
    assert "eve_indexer_started" not in events
    assert "alert_dispatcher_started" not in events
    assert "eve_indexer_stopped" not in events
    assert "alert_dispatcher_stopped" not in events


async def test_blocked_startup_still_starts_eve_cleanup(tmp_path: Path) -> None:
    """eve_cleanup has no dependency on the eve.json mount — retention must
    keep running on a blocked box, unlike the pipeline and worker above.
    Dedicated assertion (not just riding along on the tasks-list equality
    check above) so this specific invariant has its own regression guard."""
    cfg = _cfg(
        tmp_path,
        eve_log_path=str(tmp_path / "missing-eve.json"),
        suricata_config_path=str(_REFERENCE_YAML),
    )
    app = FastAPI()

    with capture_logs() as logs:
        async with _build_lifespan(cfg)(app):
            # Task creation alone only schedules the task — give the event
            # loop one real turn so eve_cleanup's own startup line actually
            # runs before the lifespan's finally cancels every task.
            await asyncio.sleep(0)

    started = next(e for e in logs if e["event"] == "verdix_started")
    assert "eve_cleanup" in started["tasks"]
    assert any(e["event"] == "eve_cleanup_task_started" for e in logs)


async def test_blocked_startup_logs_the_block_reason_clearly(tmp_path: Path) -> None:
    """Previously nothing logged *why* the pipeline died on a blocked boot —
    eve_tailer_started never appeared and there was no single line naming
    the reason. `ingestion_blocked_at_startup` is that line."""
    cfg = _cfg(
        tmp_path,
        eve_log_path=str(tmp_path / "missing-eve.json"),
        suricata_config_path=str(_REFERENCE_YAML),
    )
    app = FastAPI()

    with capture_logs() as logs:
        async with _build_lifespan(cfg)(app):
            pass

    blocked_log = next(e for e in logs if e["event"] == "ingestion_blocked_at_startup")
    assert blocked_log["log_level"] == "error"
    assert "eve.json unreadable" in blocked_log["reason"]


async def test_unblocked_startup_still_creates_pipeline_and_worker_tasks(
    tmp_path: Path,
) -> None:
    """Companion to the defect-1 tests above: proves the tightened guard
    (suricata_config is not None AND not blocking_reasons) doesn't regress
    the ordinary case where both paths are readable."""
    eve_path = tmp_path / "eve.json"
    eve_path.write_text("")
    cfg = _cfg(
        tmp_path,
        eve_log_path=str(eve_path),
        suricata_config_path=str(_REFERENCE_YAML),
    )
    app = FastAPI()

    with capture_logs() as logs:
        async with _build_lifespan(cfg)(app):
            pass

    started = next(e for e in logs if e["event"] == "verdix_started")
    assert started["ingestion_active"] is True
    assert set(started["tasks"]) == {"eve_pipeline", "triage_worker", "eve_cleanup"}
    assert app.state.ingestion_status.blocked_reason is None
