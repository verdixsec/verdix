# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Verdix application entrypoint — full production wiring.

All long-running components start via FastAPI lifespan so uvicorn handles
SIGTERM/SIGINT and background tasks are cancelled cleanly on shutdown.

Startup order:
  1. configure_logging() — structured JSON to stdout
  2. init_db()           — creates SQLite schema via SQLAlchemy create_all
  3. configure_stores()  — wire EventStore / OperationalStore / DispositionStore
  4. read_config()       — parse suricata.yaml (degrades gracefully if absent)
  5. EvePipeline         — background task: tail eve.json → index → dispatch
  6. TriageWorker        — background task: dequeue → enrich → LLM → persist
  7. EveCleanupTask      — background task: nightly retention cleanup
  8. uvicorn             — serve the FastAPI web application

Usage:
    python -m src.main
    VX_ADMIN_PASSWORD=pw VX_EVE_LOG_PATH=/path/to/eve.json python -m src.main
"""
from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any, AsyncIterator

import structlog

if TYPE_CHECKING:
    from fastapi import FastAPI

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Environment → config dict
# ---------------------------------------------------------------------------

def _read_env() -> dict[str, Any]:
    db_path = os.environ.get("VX_DB_PATH", "verdix.db")
    return {
        "db_path": db_path,
        "cache_db_path": _sibling_path(db_path, "cache.db"),
        "host": os.environ.get("VX_HOST", "0.0.0.0"),
        "port": int(os.environ.get("VX_PORT", "8080")),
        "log_level": os.environ.get("VX_LOG_LEVEL", "INFO"),
        # EVE ingestion
        "eve_log_path": os.environ.get(
            "VX_EVE_LOG_PATH", "/host/suricata/logs/eve.json"
        ),
        "suricata_config_path": os.environ.get(
            "VX_SURICATA_CONFIG_PATH", "/host/suricata/config/suricata.yaml"
        ),
        "poll_interval_ms": int(os.environ.get("VX_EVE_POLL_INTERVAL_MS", "500")),
        "context_delay_s": float(
            os.environ.get("VX_FLOW_CONTEXT_DELAY_SECONDS", "30")
        ),
        # Triage
        "daily_cap": int(os.environ.get("VX_TRIAGE_DAILY_CAP", "300")),
        "retention_days": int(os.environ.get("VX_EVE_CONTEXT_RETENTION_DAYS", "7")),
        # LLM
        "ollama_url": os.environ.get("VX_OLLAMA_URL", "http://llm:11434/api/chat"),
        "ollama_model": os.environ.get("VX_OLLAMA_MODEL", "gemma4:e4b-it-q8_0"),
        "ollama_timeout": float(os.environ.get("VX_OLLAMA_TIMEOUT_SECONDS", "600")),
        # Enrichment
        "geoip_country_db": os.environ.get(
            "VX_GEOIP_COUNTRY_DB_PATH",
            "/var/lib/verdix/geoip/dbip-country-lite.mmdb",
        ),
        "geoip_asn_db": os.environ.get(
            "VX_GEOIP_ASN_DB_PATH",
            "/var/lib/verdix/geoip/dbip-asn-lite.mmdb",
        ),
        "vt_api_key": os.environ.get("VX_VIRUSTOTAL_API_KEY"),
    }


def _sibling_path(base: str, name: str) -> str:
    """Return a path in the same directory as base with the given filename."""
    import os.path
    return os.path.join(os.path.dirname(os.path.abspath(base)), name)


# ---------------------------------------------------------------------------
# FastAPI lifespan — starts / stops all background components
# ---------------------------------------------------------------------------

def _build_lifespan(cfg: dict[str, Any]):
    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        from src.enrichment.maxmind.client import GeoIPClient
        from src.enrichment.rdap.client import RDAPClient
        from src.enrichment.virustotal.client import VirusTotalClient
        from src.identity.reverse_dns.provider import ReverseDNSIdentityProvider
        from src.infra.cache.sqlite import SQLiteCache
        from src.infra.db.disposition_store import SQLiteDispositionStore
        from src.infra.db.event_store import SQLiteEventStore
        from src.infra.db.operational_store import SQLiteOperationalStore
        from src.infra.db.session import close_db, init_db
        from src.infra.suricata_config.reader import read_config
        from src.llm.ollama_client import OllamaClient
        from src.triage.cleanup import EveCleanupTask
        from src.triage.worker import TriageWorker
        from src.web.deps import configure_stores

        db_url = f"sqlite+aiosqlite:///{cfg['db_path']}"

        # 1. Database
        await init_db(db_url)
        event_store = SQLiteEventStore()
        operational_store = SQLiteOperationalStore()
        disposition_store = SQLiteDispositionStore()
        configure_stores(event_store, operational_store, disposition_store)
        logger.info("stores_configured", db_path=cfg["db_path"])

        # Ensure the opaque install UUID exists (idempotent)
        from src.telemetry.install_id import ensure_install_id
        await ensure_install_id(operational_store)

        # Live ingestion health (ADR-019). Constructed before the startup
        # checks below so a blocked state can be recorded during them.
        from src.ingestion.status import IngestionStatus

        ingestion_status = IngestionStatus(poll_interval_ms=cfg["poll_interval_ms"])
        app.state.ingestion_status = ingestion_status
        blocking_reasons: list[str] = []

        # 2. Suricata config — degrade gracefully on missing file
        suricata_config = None
        try:
            suricata_config = read_config(cfg["suricata_config_path"])
            logger.info(
                "suricata_config_loaded",
                home_net_ranges=len(suricata_config.home_net),
                path=cfg["suricata_config_path"],
            )
        except Exception as exc:
            logger.warning(
                "suricata_config_unavailable",
                error=str(exc),
                detail=(
                    "Ingestion and triage will not start. "
                    "Correct VX_SURICATA_CONFIG_PATH and restart."
                ),
            )
            blocking_reasons.append(
                f"suricata.yaml unreadable at {cfg['suricata_config_path']}: {exc}"
            )

        # eve.json — no explicit startup check previously existed; an
        # unreadable path only surfaced later, the first time the tailer
        # polled (the 2026-08-12 mechanism). Check it at boot too.
        eve_path = cfg["eve_log_path"]
        if not (os.path.isfile(eve_path) and os.access(eve_path, os.R_OK)):
            logger.warning(
                "eve_log_unavailable_at_startup",
                path=eve_path,
                detail="Ingestion will not start. Correct VX_EVE_LOG_PATH and restart.",
            )
            blocking_reasons.append(f"eve.json unreadable at {eve_path}")

        if blocking_reasons:
            blocked_reason = "; ".join(blocking_reasons)
            ingestion_status.record_blocked(blocked_reason)
            logger.error(
                "ingestion_blocked_at_startup",
                reason=blocked_reason,
                detail=(
                    "Ingestion and triage will not start this boot. "
                    "See /setup/health."
                ),
            )

        # 3. Shared cache (one SQLite file; enrichment clients use distinct key prefixes)
        cache = SQLiteCache(cfg["cache_db_path"])

        # 4. Enrichment clients
        vt_client = (
            VirusTotalClient(cache, api_key=cfg["vt_api_key"])
            if cfg["vt_api_key"]
            else None
        )
        geoip_client = GeoIPClient(
            country_db_path=cfg["geoip_country_db"],
            asn_db_path=cfg["geoip_asn_db"],
        )
        rdap_client = RDAPClient(cache)

        # 5. LLM
        # Pin greedy decoding (temperature 0): the validated baseline. Accuracy and
        # FNR were measured at temp 0, so production must match for deterministic verdicts.
        llm = OllamaClient(
            model=cfg["ollama_model"],
            base_url=cfg["ollama_url"],
            timeout=cfg["ollama_timeout"],
            temperature=0.0,
        )

        # 6. Background tasks
        background_tasks: list[asyncio.Task] = []

        # Blocked startup (ADR-019 sec. 1) must not construct or start the
        # pipeline/worker at all — starting them and letting the tailer fail
        # immediately reproduces the exact eve_indexer_stopped/
        # alert_dispatcher_stopped signature the 2026-08-12 incident left
        # behind, on the path built to eliminate it. The condition is
        # inlined (not hoisted to a bool) so mypy narrows suricata_config to
        # non-None inside this block.
        pipeline_started = False
        if suricata_config is not None and not blocking_reasons:
            pipeline_started = True
            from src.ingestion.pipeline import EvePipeline

            identity_provider = ReverseDNSIdentityProvider(
                config=suricata_config, cache=cache
            )
            pipeline = EvePipeline(
                eve_path=cfg["eve_log_path"],
                event_store=event_store,
                poll_interval_ms=cfg["poll_interval_ms"],
                context_delay_seconds=cfg["context_delay_s"],
                daily_cap=cfg["daily_cap"],
                status=ingestion_status,
            )
            worker = TriageWorker(
                event_store=event_store,
                operational_store=operational_store,
                llm=llm,
                suricata_config=suricata_config,
                identity_provider=identity_provider,
                vt_client=vt_client,
                geoip_client=geoip_client,
                rdap_client=rdap_client,
                daily_cap=cfg["daily_cap"],
            )
            background_tasks.append(
                asyncio.create_task(pipeline.run(), name="eve_pipeline")
            )
            background_tasks.append(
                asyncio.create_task(worker.run(), name="triage_worker")
            )

        cleanup = EveCleanupTask(event_store, retention_days=cfg["retention_days"])
        background_tasks.append(
            asyncio.create_task(cleanup.run_nightly(), name="eve_cleanup")
        )

        logger.info(
            "verdix_started",
            tasks=[t.get_name() for t in background_tasks],
            ingestion_active=pipeline_started,
        )

        try:
            yield
        finally:
            logger.info("verdix_shutting_down")
            for task in background_tasks:
                task.cancel()
            await asyncio.gather(*background_tasks, return_exceptions=True)
            await close_db()
            logger.info("verdix_stopped")

    return lifespan


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    import uvicorn
    from src.infra.logging import configure_logging

    cfg = _read_env()
    configure_logging(cfg["log_level"])

    if not os.environ.get("VX_ADMIN_PASSWORD"):
        logger.warning(
            "vx_admin_password_not_set",
            detail="Set VX_ADMIN_PASSWORD before exposing the web UI.",
        )

    from src.web.app import create_app
    app = create_app(lifespan=_build_lifespan(cfg))

    uvicorn.run(
        app,
        host=cfg["host"],
        port=cfg["port"],
        # Disable uvicorn's log config — structlog owns all logging
        log_config=None,
    )


if __name__ == "__main__":
    main()
