# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Triage worker — dequeues alerts and runs the full verdict pipeline.

Pipeline per alert (ADR-009, ADR-010, ADR-007, ADR-012):
  1. Dequeue next 'queued' alert (honours daily cap)
  2. Mark alert 'analyzing'
  3. Fetch correlated EVE events from EventStore (flow_id window)
  4. Deterministic role assignment (assigner.assign_roles)
  5. Identity resolution via IdentityProvider (src_ip + dst_ip)
  6. Parallel enrichment — VT + MaxMind + RDAP per extracted indicator
  7. Build prompt via PromptBuilder
  8. LLM verdict via LLMProvider
  9. Persist verdict + evidence chain to OperationalStore
 10. Link verdict_id back to alert row; mark 'analyzed'
 11. Persist role assignment to alert row (EventStore)

On any unhandled exception the alert is marked 'failed' and the worker
continues with the next alert — never crashes the process.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import uuid
from datetime import UTC, datetime
from typing import Any

import structlog

from src.domain.role_assignment.assigner import assign_roles
from src.domain.role_assignment.models import RoleAssignment
from src.enrichment.models import (
    EnrichmentResult,
    EnrichmentStatus,
    Indicator,
    IndicatorType,
)
from src.identity.models import IdentityFacts
from src.infra.logging import bind_alert_context, clear_alert_context
from src.infra.suricata_config.models import SuricataConfig
from src.interfaces.event_store import EventStore
from src.interfaces.llm_provider import LLMProvider
from src.interfaces.operational_store import OperationalStore
from src.llm.ollama_client import OllamaClient
from src.llm.prompt_builder import PromptBuilder, build_enrichment_context

logger = structlog.get_logger(__name__)

_POLL_INTERVAL_SECONDS = float(os.environ.get("VX_TRIAGE_POLL_INTERVAL_SECONDS", "2"))
_DEFAULT_DAILY_CAP = int(os.environ.get("VX_TRIAGE_DAILY_CAP", "300"))

# Maximum indicators sent to VT/RDAP per alert to protect free-tier quota.
_MAX_IPS = 2
_MAX_DOMAINS = 3

# Internal-only name suffixes. Domains under these are never extracted as
# indicators, so they never reach VT or RDAP.
_INTERNAL_DOMAIN_SUFFIXES = (
    ".local", ".lan", ".internal", ".corp", ".home", ".home.arpa", ".localdomain",
)

# RFC 6598 shared address space (carrier-grade NAT). Python's ipaddress does
# not class it as private or reserved, so it needs an explicit check.
_CGNAT_NET = ipaddress.ip_network("100.64.0.0/10")


class TriageWorker:
    """Single async triage worker — runs as a long-lived coroutine.

    Instantiated once at application startup with all dependencies injected.
    Call run() to start the dequeue loop; cancel the task to stop cleanly.

    Args:
        event_store:        EventStore for alert/EVE reads and status updates.
        operational_store:  OperationalStore for verdict persistence.
        llm:                LLMProvider (OllamaClient in production).
        suricata_config:    Parsed SuricataConfig for role assignment and prompt.
        identity_provider:  Optional IdentityProvider (ReverseDNSIdentityProvider).
        vt_client:          Optional VirusTotalClient; None → NOT_CONFIGURED.
        geoip_client:       Optional GeoIPClient; None → NOT_CONFIGURED.
        rdap_client:        Optional RDAPClient; None → NOT_CONFIGURED.
        daily_cap:          Max alerts auto-analyzed per day (VX_TRIAGE_DAILY_CAP).
    """

    def __init__(
        self,
        event_store: EventStore,
        operational_store: OperationalStore,
        llm: LLMProvider,
        suricata_config: SuricataConfig,
        *,
        identity_provider: Any = None,
        vt_client: Any = None,
        geoip_client: Any = None,
        rdap_client: Any = None,
        daily_cap: int = _DEFAULT_DAILY_CAP,
    ) -> None:
        self._event_store = event_store
        self._operational_store = operational_store
        self._llm = llm
        self._config = suricata_config
        self._identity = identity_provider
        self._vt = vt_client
        self._geoip = geoip_client
        self._rdap = rdap_client
        self._daily_cap = daily_cap
        self._prompt_builder = PromptBuilder()

    async def run(self) -> None:
        """Main dequeue loop — runs until the task is cancelled."""
        logger.info("triage_worker_started", daily_cap=self._daily_cap)
        while True:
            try:
                alert = await self._dequeue_next()
                if alert is None:
                    await asyncio.sleep(_POLL_INTERVAL_SECONDS)
                    continue
                await self._process_alert(alert)
            except asyncio.CancelledError:
                logger.info("triage_worker_stopped")
                raise
            except Exception as exc:
                logger.error("triage_worker_loop_error", error=str(exc))
                await asyncio.sleep(_POLL_INTERVAL_SECONDS)

    # ------------------------------------------------------------------
    # Dequeue
    # ------------------------------------------------------------------

    async def _dequeue_next(self) -> dict[str, Any] | None:
        """Return the next 'queued' alert, or None if cap reached / queue empty."""
        count = await self._event_store.count_analyzed_today()
        if count >= self._daily_cap:
            return None
        alerts = await self._event_store.query_alerts(status="queued", limit=1, offset=0)
        return alerts[0] if alerts else None

    # ------------------------------------------------------------------
    # Per-alert pipeline
    # ------------------------------------------------------------------

    async def _process_alert(self, alert: dict[str, Any]) -> None:
        alert_id = alert["alert_id"]
        # Bind alert_id into structlog's contextvars (merged into every log
        # line via the merge_contextvars processor, src/infra/logging/setup.py)
        # so modules called deeper in the pipeline -- OllamaClient's retry
        # logging in particular -- carry alert_id without needing it threaded
        # through every function signature.
        bind_alert_context(alert_id)
        # signature_id/src_ip/dst_ip bound here so every line this alert emits
        # (including verdict_produced/verdict_inherited below) carries its
        # dedup group key — lets a load-test run's dequeue order and
        # inheritance eligibility be reconstructed from logs alone, with no
        # cross-reference to the alerts table.
        log = logger.bind(
            alert_id=alert_id,
            signature_id=alert.get("signature_id"),
            src_ip=alert.get("src_ip"),
            dst_ip=alert.get("dst_ip"),
        )
        # INFO, not DEBUG: this is the processing-start marker used to
        # reconstruct per-alert dequeue order. A load-test run should not
        # need VX_LOG_LEVEL=DEBUG just to get this one line.
        log.info("alert_dequeued")

        try:
            await self._event_store.update_alert_status(alert_id, "analyzing")

            # Parse raw EVE JSON for this alert.
            raw_eve: dict[str, Any] = json.loads(alert["raw_eve"])

            # 1. Correlated EVE events from EventStore.
            flow_id = alert.get("flow_id")
            correlated_rows: list[dict[str, Any]] = []
            if flow_id:
                correlated_rows = await self._event_store.get_correlated_events(flow_id)
            correlated_events = [json.loads(r["raw_eve"]) for r in correlated_rows]

            # 2. Role assignment.
            role = assign_roles(raw_eve, self._config)
            await self._event_store.update_alert_role_assignment(alert_id, role)
            log.debug("role_assigned", confidence=role.confidence)

            # 3. Dedup check — before enrichment so we skip DNS/GeoIP/VT API calls
            #    for beaconing alerts that repeat the same (sig, src, dst) pattern.
            source_verdict_id = await self._event_store.find_recent_verdict_for_group(
                alert.get("signature_id"),
                alert.get("src_ip"),
                alert.get("dst_ip"),
                alert["ingest_timestamp"],
            )
            if source_verdict_id:
                source = await self._operational_store.get_verdict(source_verdict_id)
            else:
                source = None

            if source:
                log.info(
                    "verdict_inherited",
                    source_verdict_id=source_verdict_id,
                    category=source["verdict_category"],
                )
                verdict_id = str(uuid.uuid4())
                await self._operational_store.mark_previous_verdicts_superseded(alert_id)
                await self._operational_store.record_verdict({
                    "verdict_id": verdict_id,
                    "alert_id": alert_id,
                    "verdict_category": source["verdict_category"],
                    "confidence_score": source["confidence_score"],
                    "reasoning": source["reasoning"],
                    "contributing_facts": source["contributing_facts"],
                    "evidence_chain": source["evidence_chain"],
                    "model_version": source["model_version"],
                    "prompt_version": source["prompt_version"],
                    "llm_inputs": json.dumps({"inherited_from": source_verdict_id}),
                    "llm_raw_output": source["llm_raw_output"],
                    "latency_ms": 0,
                    "is_current": True,
                    "created_at": datetime.now(UTC).isoformat(),
                })
                await self._operational_store.link_verdict_to_alert(alert_id, verdict_id)
                return

            # 4. Identity resolution (best-effort; never raises).
            src_identity, dst_identity = await self._resolve_identities(raw_eve)

            # 5. Parallel enrichment.
            indicators = _extract_indicators(raw_eve, correlated_events, self._config)
            enrichment_pairs = await self._enrich_all(indicators)

            # 6. Build prompt.
            enrichment_ctx = build_enrichment_context(enrichment_pairs)
            prompt = self._prompt_builder.build(
                alert=raw_eve,
                correlated_events=correlated_events,
                enrichment_context=enrichment_ctx,
                src_hostname=src_identity.hostname if src_identity else None,
                dst_hostname=dst_identity.hostname if dst_identity else None,
            )

            # 7. LLM verdict.
            response = await self._llm.complete(
                prompt,
                OllamaClient.OUTPUT_SCHEMA,
                prompt_version=self._prompt_builder.prompt_version,
            )
            log.info(
                "verdict_produced",
                category=response.verdict_category,
                confidence=response.confidence_score,
                latency_ms=response.latency_ms,
            )

            # 8. Persist.
            evidence_chain = _build_evidence_chain(
                raw_eve, correlated_events, role, src_identity, dst_identity, enrichment_pairs
            )
            verdict_id = str(uuid.uuid4())
            await self._operational_store.mark_previous_verdicts_superseded(alert_id)
            await self._operational_store.record_verdict({
                "verdict_id": verdict_id,
                "alert_id": alert_id,
                "verdict_category": response.verdict_category,
                "confidence_score": response.confidence_score,
                "reasoning": response.reasoning,
                "contributing_facts": json.dumps(response.contributing_facts),
                "evidence_chain": json.dumps(evidence_chain),
                "model_version": response.model_version,
                "prompt_version": response.prompt_version,
                "llm_inputs": json.dumps(response.llm_inputs),
                "llm_raw_output": json.dumps(response.raw_output),
                "latency_ms": response.latency_ms,
                "is_current": True,
                "created_at": datetime.now(UTC).isoformat(),
            })
            await self._operational_store.link_verdict_to_alert(alert_id, verdict_id)

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.error("triage_failed", error=str(exc))
            try:
                await self._event_store.update_alert_status(alert_id, "failed")
            except Exception:
                pass
        finally:
            clear_alert_context()

    # ------------------------------------------------------------------
    # Identity helpers
    # ------------------------------------------------------------------

    async def _resolve_identities(
        self, raw_eve: dict[str, Any]
    ) -> tuple[IdentityFacts | None, IdentityFacts | None]:
        if self._identity is None:
            return None, None
        src_ip = raw_eve.get("src_ip", "")
        dst_ip = raw_eve.get("dest_ip", "")
        src_task = self._identity.resolve_ip(src_ip) if src_ip else _noop()
        dst_task = self._identity.resolve_ip(dst_ip) if dst_ip else _noop()
        src_id, dst_id = await asyncio.gather(src_task, dst_task, return_exceptions=True)
        return (
            src_id if isinstance(src_id, IdentityFacts) else None,
            dst_id if isinstance(dst_id, IdentityFacts) else None,
        )

    # ------------------------------------------------------------------
    # Enrichment helpers
    # ------------------------------------------------------------------

    async def _enrich_all(
        self, indicators: list[Indicator]
    ) -> list[tuple[Indicator, EnrichmentResult]]:
        tasks = [self._enrich_one(ind) for ind in indicators]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        pairs: list[tuple[Indicator, EnrichmentResult]] = []
        for ind, res in zip(indicators, results):
            if isinstance(res, list):
                pairs.extend(res)
            else:
                # Unexpected exception — degrade to NOT_CONFIGURED.
                pairs.append((ind, EnrichmentResult.not_configured(ind.type.value)))
        return pairs

    async def _enrich_one(
        self, indicator: Indicator
    ) -> list[tuple[Indicator, EnrichmentResult]]:
        if indicator.type is IndicatorType.IP:
            # GeoIP runs on all IPs (local MMDB, no network call; returns "Private IP" for
            # RFC1918 — useful topology context). VT is skipped for private, reserved, CGNAT
            # and HOME_NET addresses — no ledger entry, because VT *is* configured; internal
            # addresses are simply never sent out.
            geo = await self._lookup(self._geoip, indicator, source="geoip")
            if not _is_public_ip(indicator.value, self._config):
                return [(indicator, geo)]
            vt = await self._lookup(self._vt, indicator, source="virustotal")
            return [(indicator, vt), (indicator, geo)]
        if indicator.type is IndicatorType.DOMAIN:
            vt, rdap = await asyncio.gather(
                self._lookup(self._vt, indicator, source="virustotal"),
                self._lookup(self._rdap, indicator, source="rdap"),
            )
            return [(indicator, vt), (indicator, rdap)]
        return [(indicator, EnrichmentResult.not_configured(indicator.type.value))]

    async def _lookup(
        self, client: Any, indicator: Indicator, *, source: str = ""
    ) -> EnrichmentResult:
        if client is None:
            return EnrichmentResult.not_configured(source or indicator.type.value)
        try:
            return await client.lookup(indicator)
        except Exception as exc:
            from src.enrichment.models import FailureReason
            return EnrichmentResult.failing(
                source=getattr(client, "_SOURCE", source) or source or "unknown",
                reason=FailureReason.OTHER,
                detail=str(exc),
            )


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------

async def _noop() -> None:
    return None


def _is_public_ip(ip: str, config: SuricataConfig | None = None) -> bool:
    """Return True only for IPs that may be sent to VT.

    False for private, loopback, link-local, reserved, multicast and CGNAT
    (100.64.0.0/10) addresses, and, when config is given, for any HOME_NET
    address, including public ranges the customer owns.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if (
        addr.is_private or addr.is_loopback or addr.is_link_local
        or addr.is_reserved or addr.is_multicast
    ):
        return False
    if addr.version == 4 and addr in _CGNAT_NET:
        return False
    if config is not None and "HOME_NET" in config.membership_for_ip(ip):
        return False
    return True


def _is_internal_domain_name(domain: str) -> bool:
    """True when the name sits under an internal-only suffix (.local, .corp, ...)."""
    name = domain.lower().rstrip(".")
    return any(
        name == suffix[1:] or name.endswith(suffix)
        for suffix in _INTERNAL_DOMAIN_SUFFIXES
    )


def _dns_answer_ips(correlated_events: list[dict[str, Any]]) -> dict[str, set[str]]:
    """Map each queried/answered name in the flow's dns events to its A/AAAA answers.

    Handles every EVE shape seen so far: Suricata 8.x nested answers
    (dns.answers[]), the grouped format (dns.grouped.A/AAAA), and per-record
    answer events (dns.type == "answer" with flat rrname/rdata). Every IP
    answer in an event is attributed to the event's query name as well as the
    answer's own rrname, so a CNAME chain cannot hide a HOME_NET answer.
    Non-IP rdata (CNAME targets, TXT, ...) is ignored.
    """
    answers: dict[str, set[str]] = {}

    def _add(names: list[str], rdata: Any) -> None:
        if not isinstance(rdata, str):
            return
        try:
            ipaddress.ip_address(rdata)
        except ValueError:
            return
        for name in names:
            if name:
                answers.setdefault(name.lower().rstrip("."), set()).add(rdata)

    for event in correlated_events:
        if event.get("event_type") != "dns":
            continue
        dns = event.get("dns") or {}
        names: list[str] = [dns.get("rrname") or ""]
        queries = dns.get("queries") or []
        if isinstance(queries, dict):
            queries = [queries]
        if isinstance(queries, list):
            names += [(q or {}).get("rrname") or "" for q in queries if isinstance(q, dict)]

        _add(names, dns.get("rdata"))
        for ans in dns.get("answers") or []:
            if isinstance(ans, dict):
                _add(names + [ans.get("rrname") or ""], ans.get("rdata"))
        grouped = dns.get("grouped") or {}
        if isinstance(grouped, dict):
            for rrtype in ("A", "AAAA"):
                for rdata in grouped.get(rrtype) or []:
                    _add(names, rdata)
    return answers


def _server_ip(event: dict[str, Any]) -> str | None:
    """Return the server endpoint of an http/tls event.

    Suricata logs app-layer transactions client-to-server, so the server is
    dest_ip. Every http/tls record in the eval corpus follows this, including
    17 on high server ports, which is why port numbers are not used to guess
    the side. An explicit direction of "to_client" flips it to src_ip.
    """
    if event.get("direction") == "to_client":
        return event.get("src_ip")
    return event.get("dest_ip")


def _extract_indicators(
    raw_eve: dict[str, Any],
    correlated_events: list[dict[str, Any]],
    config: SuricataConfig | None = None,
) -> list[Indicator]:
    """Extract up to _MAX_IPS IP indicators and _MAX_DOMAINS domain indicators.

    Internal names are never returned as domain indicators: names under an
    internal-only suffix and, when config is given, any name whose DNS answer
    in the flow's dns events is a HOME_NET address, or any http.hostname /
    tls.sni whose event's server IP is in HOME_NET. Skipped names do not
    count toward _MAX_DOMAINS.
    """
    home_net_names: set[str] = set()
    if config is not None:
        home_net_names = {
            name
            for name, answer_ips in _dns_answer_ips(correlated_events).items()
            if any("HOME_NET" in config.membership_for_ip(ip) for ip in answer_ips)
        }

    ips: list[str] = []
    for field in ("src_ip", "dest_ip"):
        ip = raw_eve.get(field)
        if ip and ip not in ips:
            ips.append(ip)
        if len(ips) >= _MAX_IPS:
            break

    domains: list[str] = []
    for event in correlated_events:
        etype = event.get("event_type")
        domain: str | None = None
        # Set only for http/tls, where the event's server endpoint is known.
        # Not for dns: its dest_ip is the resolver, which is usually internal.
        server_ip: str | None = None
        if etype == "dns":
            dns = event.get("dns") or {}
            # Suricata 7.x: flat dns.rrname; Suricata 8.x EVE v2: dns.queries[0].rrname
            domain = dns.get("rrname") or ""
            if not domain:
                queries = dns.get("queries") or []
                if isinstance(queries, list) and queries:
                    domain = (queries[0] or {}).get("rrname", "")
                elif isinstance(queries, dict):
                    domain = queries.get("rrname", "")
        elif etype == "http":
            domain = (event.get("http") or {}).get("hostname") or ""
            server_ip = _server_ip(event)
        elif etype == "tls":
            domain = (event.get("tls") or {}).get("sni") or ""
            server_ip = _server_ip(event)
        if domain and "." in domain and domain not in domains and not domain.endswith(".arpa"):
            # http.hostname / tls.sni / dns.rrname may contain a bare IP address
            # (client connected directly to IP). Route it to the IP list rather
            # than sending it to VT's /domains/ endpoint (which returns 400 for IPs).
            # _is_public_ip() filters it in _enrich_one() like any other IP.
            try:
                ipaddress.ip_address(domain)
                if domain not in ips and len(ips) < _MAX_IPS:
                    ips.append(domain)
            except ValueError:
                if _is_internal_domain_name(domain):
                    continue
                if domain.lower().rstrip(".") in home_net_names:
                    continue
                if (
                    config is not None and server_ip
                    and "HOME_NET" in config.membership_for_ip(server_ip)
                ):
                    continue
                domains.append(domain)
        if len(domains) >= _MAX_DOMAINS:
            break

    indicators: list[Indicator] = [Indicator(type=IndicatorType.IP, value=ip) for ip in ips]
    indicators += [Indicator(type=IndicatorType.DOMAIN, value=d) for d in domains]
    return indicators


def _best_result(a: EnrichmentResult, b: EnrichmentResult) -> EnrichmentResult:
    """Return the result with more information (CONTRIBUTED > FAILING > NOT_CONFIGURED)."""
    _rank = {
        EnrichmentStatus.CONTRIBUTED: 2,
        EnrichmentStatus.FAILING: 1,
        EnrichmentStatus.NOT_CONFIGURED: 0,
    }
    return a if _rank[a.status] >= _rank[b.status] else b


def _identity_to_dict(facts: IdentityFacts | None) -> dict[str, Any] | None:
    if facts is None:
        return None
    return {
        "ip": facts.ip,
        "hostname": facts.hostname,
        "username": facts.username,
        "ou_path": facts.ou_path,
        "group_memberships": facts.group_memberships,
        "source": facts.source,
        "queried_at": facts.queried_at.isoformat(),
    }


def _enrichment_result_to_dict(result: EnrichmentResult) -> dict[str, Any]:
    return {
        "source": result.source,
        "status": result.status.value,
        "data": result.data,
        "summary": result.summary,
        "failure_reason": result.failure_reason.value if result.failure_reason else None,
        "failure_detail": result.failure_detail,
        "cached": result.cached,
        "cache_age_seconds": result.cache_age_seconds,
        "queried_at": result.queried_at.isoformat(),
    }


def _build_evidence_chain(
    raw_eve: dict[str, Any],
    correlated_events: list[dict[str, Any]],
    role: RoleAssignment,
    src_identity: IdentityFacts | None,
    dst_identity: IdentityFacts | None,
    enrichment_pairs: list[tuple[Indicator, EnrichmentResult]],
) -> dict[str, Any]:
    """Build the JSON-serializable evidence chain dict stored with each verdict."""
    return {
        "alert": raw_eve,
        "correlated_events": correlated_events,
        "role_assignment": {
            "initiator_ip": role.initiator_ip,
            "responder_ip": role.responder_ip,
            "attacker_ip": role.attacker_ip,
            "victim_ip": role.victim_ip,
            "confidence": role.confidence,
            "reasoning": role.reasoning,
            "signals_used": role.signals_used,
        },
        "identity": {
            "src": _identity_to_dict(src_identity),
            "dst": _identity_to_dict(dst_identity),
        },
        "enrichment_ledger": [
            {
                "indicator": ind.value,
                "indicator_type": ind.type.value,
                **_enrichment_result_to_dict(result),
            }
            for ind, result in enrichment_pairs
        ],
    }
