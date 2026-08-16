# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Per-alert investigation view and disposition endpoint."""
from __future__ import annotations

import json

from fastapi import APIRouter, Form, Request
from fastapi.responses import JSONResponse, RedirectResponse

from src.web.app import templates
from src.web.auth import is_authenticated
from src.web.deps import get_disposition_store, get_event_store, get_operational_store

router = APIRouter()


@router.get("/alert/{alert_id}")
async def get_alert(request: Request, alert_id: str):
    if not is_authenticated(request):
        return RedirectResponse("/login", status_code=303)

    event_store = get_event_store()
    op_store = get_operational_store()
    disp_store = get_disposition_store()

    alert = await event_store.get_alert(alert_id)
    if alert is None:
        return templates.TemplateResponse(
            request,
            "queue.html",
            {
                "error": f"Alert {alert_id} not found",
                "rows": [], "window": "24h", "status_filter": "all",
                "queued_count": 0, "analyzing_count": 0, "failed_count": 0,
                "deferred_count": 0, "total": 0, "time_behind": None,
                "ingestion": {"state": "green"},
            },
            status_code=404,
        )

    # Verdict
    verdict = None
    evidence_chain: dict = {}
    llm_inputs_preview = ""
    is_inherited = False
    source_alert_id: str | None = None
    if alert.get("verdict_id"):
        verdict = await op_store.get_verdict(alert["verdict_id"])
        if verdict:
            try:
                evidence_chain = json.loads(verdict.get("evidence_chain") or "{}")
            except (json.JSONDecodeError, TypeError):
                evidence_chain = {}
            try:
                raw_in = json.loads(verdict.get("llm_inputs") or "{}")
                source_verdict_id_ref = raw_in.get("inherited_from")
                if source_verdict_id_ref:
                    # Inherited verdict — resolve source alert for the link.
                    is_inherited = True
                    source_v = await op_store.get_verdict(source_verdict_id_ref)
                    if source_v:
                        source_alert_id = source_v.get("alert_id")
                else:
                    llm_inputs_preview = json.dumps(raw_in, indent=2)
            except (json.JSONDecodeError, TypeError):
                llm_inputs_preview = verdict.get("llm_inputs", "")

    # Disposition
    disposition = await disp_store.get_latest_disposition(alert_id)

    # Correlated flow events
    correlated: list[dict] = []
    if alert.get("flow_id"):
        raw_events = await event_store.get_correlated_events(alert["flow_id"])
        # Parse and summarise all events, then collapse consecutive identical rows.
        parsed_events: list[dict] = []
        for ev in raw_events[:200]:
            try:
                parsed = json.loads(ev.get("raw_eve") or "{}")
            except (json.JSONDecodeError, TypeError):
                parsed = {}
            parsed_events.append({
                "event_type": ev.get("event_type", "unknown"),
                "event_timestamp": ev.get("event_timestamp"),
                "summary": _summarise_event(parsed),
            })
        # Global dedup: collapse any identical (event_type, summary) pairs regardless
        # of order, preserving first-occurrence position. This handles interleaved
        # repeating events (e.g. alternating CO-ALERT / HTTP from beaconing PCAPs)
        # that consecutive-only collapsing misses.
        seen_keys: dict[tuple, int] = {}  # (event_type, summary) -> index in correlated
        for ev in parsed_events:
            if not ev["summary"]:
                continue
            key = (ev["event_type"], ev["summary"])
            if key in seen_keys:
                correlated[seen_keys[key]]["count"] += 1
            else:
                seen_keys[key] = len(correlated)
                correlated.append({**ev, "count": 1})

    # Enrichment ledger from evidence_chain
    enrichment_ledger = list(evidence_chain.get("enrichment_ledger", []))

    # Build IP→hostname lookup for role card display
    identity = evidence_chain.get("identity", {})
    ip_to_hostname: dict[str, str] = {}
    for _side in ("src", "dst"):
        _ident = identity.get(_side)
        if _ident and _ident.get("hostname"):
            ip_to_hostname[_ident["ip"]] = _ident["hostname"]

    # Synthesize reverse DNS entries from identity data so they appear in the ledger
    seen_ips: set[str] = set()
    for side in ("src", "dst"):
        ident = identity.get(side)
        if ident is None:
            continue
        ip = ident.get("ip", "")
        if not ip or ip in seen_ips:
            continue
        seen_ips.add(ip)
        hostname = ident.get("hostname")
        enrichment_ledger.append({
            "indicator": ip,
            "indicator_type": "ip",
            "source": "reverse_dns",
            "status": "contributed" if hostname else "failing",
            "summary": hostname,
            "failure_reason": None if hostname else "no_ptr_record",
            "failure_detail": None if hostname else "No PTR record found",
            "cached": False,
            "cache_age_seconds": None,
        })

    # Contributing facts as list
    contributing_facts: list[str] = []
    if verdict:
        try:
            contributing_facts = json.loads(verdict.get("contributing_facts") or "[]")
        except (json.JSONDecodeError, TypeError):
            contributing_facts = []

    # Role assignment signals as list
    role_signals: list[str] = []
    try:
        role_signals = json.loads(alert.get("role_assignment_signals") or "[]")
    except (json.JSONDecodeError, TypeError):
        role_signals = []

    return templates.TemplateResponse(request, "alert.html", {
        "alert": alert,
        "verdict": verdict,
        "disposition": disposition,
        "correlated": correlated,
        "enrichment_ledger": enrichment_ledger,
        "contributing_facts": contributing_facts,
        "role_signals": role_signals,
        "llm_inputs_preview": llm_inputs_preview,
        "evidence_chain": evidence_chain,
        "ip_to_hostname": ip_to_hostname,
        "is_inherited": is_inherited,
        "source_alert_id": source_alert_id,
    })


@router.post("/alert/{alert_id}/disposition")
async def post_disposition(
    request: Request,
    alert_id: str,
    action: str = Form(...),
    override_reason: str = Form(""),
):
    if not is_authenticated(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    if action not in ("accept", "override"):
        return JSONResponse({"error": "invalid action"}, status_code=400)

    op_store = get_operational_store()
    disp_store = get_disposition_store()

    alert = await op_store.get_current_verdict_for_alert(alert_id)
    verdict_id = alert["verdict_id"] if alert else None

    # Record the disposition
    disposition_id = await disp_store.record_disposition({
        "alert_id": alert_id,
        "verdict_id": verdict_id,
        "analyst_user_id": "admin",
        "disposition_action": action,
        "override_reason_freetext": override_reason.strip() or None,
    })

    # Link back to alert row
    await op_store.link_disposition_to_alert(alert_id, disposition_id)

    return RedirectResponse("/queue", status_code=303)


def _summarise_event(ev: dict) -> str:
    etype = ev.get("event_type", "")
    if etype == "flow":
        proto = ev.get("proto", "TCP")
        src = f"{ev.get('src_ip', '?')}:{ev.get('src_port', '?')}"
        dst = f"{ev.get('dest_ip', '?')}:{ev.get('dest_port', '?')}"
        ts = ev.get("flow", {}).get("bytes_toserver", "?")
        tc = ev.get("flow", {}).get("bytes_toclient", "?")
        return f"{proto} {src} -> {dst}  bytes_toserver={ts} bytes_toclient={tc}"
    if etype == "http":
        http = ev.get("http", {})
        method = http.get("http_method", "GET")
        url = http.get("url", "/")
        status = http.get("status", "")
        host = http.get("hostname", ev.get("dest_ip", ""))
        return f"{method} {host}{url} ({status})"
    if etype == "dns":
        dns = ev.get("dns", {})
        # rrname is flat in EVE DNS v1; nested in queries[] in Suricata 8.x EVE DNS v2
        rrname = dns.get("rrname", "")
        if not rrname:
            queries = dns.get("queries", [])
            if queries:
                rrname = queries[0].get("rrname", "")
        rrname = rrname or "?"
        qtype = dns.get("type", "query")
        return f"DNS {qtype} {rrname}"
    if etype == "tls":
        tls = ev.get("tls", {})
        sni = tls.get("sni") or tls.get("subject", "?")
        return f"TLS SNI: {sni}"
    if etype == "alert":
        sig = ev.get("alert", {}).get("signature", "co-alert")
        cat = ev.get("alert", {}).get("category", "")
        return f"CO-ALERT: {sig}  [{cat}]"
    if etype == "fileinfo":
        fi = ev.get("fileinfo", {})
        filename = fi.get("filename", "") or ""
        magic = fi.get("magic", "") or ""
        size = fi.get("size")
        # Suppress trivial entries: root path with no magic and no size
        if filename in ("", "/") and not magic and size is None:
            return ""
        parts = [f"File: {filename or '/'}"]
        if magic:
            parts.append(magic)
        if size is not None:
            parts.append(f"{size} bytes")
        return "  ".join(parts) if len(parts) == 1 else f"{parts[0]} ({', '.join(parts[1:])})"
    return etype
