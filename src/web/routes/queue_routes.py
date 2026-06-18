# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Alert queue page — the analyst's primary working surface."""
from __future__ import annotations

import json
from collections import defaultdict
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse

from src.web.app import templates
from src.web.auth import is_authenticated
from src.web.deps import get_event_store, get_operational_store

router = APIRouter()

_WINDOW_HOURS = {"24h": 24, "7d": 168, "30d": 720}
_VALID_STATUS_FILTERS = {"all", "analyzed", "deferred", "queued"}
_GROUP_WINDOW_HOURS = 1  # collapse repeated (sig, src, dst) within this window


@router.get("/queue")
async def get_queue(request: Request, window: str = "24h", status: str = "all"):
    if not is_authenticated(request):
        return RedirectResponse("/login", status_code=303)

    if window not in _WINDOW_HOURS:
        window = "24h"
    if status not in _VALID_STATUS_FILTERS:
        status = "all"

    window_hours = _WINDOW_HOURS[window]
    since = datetime.now(UTC) - timedelta(hours=window_hours)

    event_store = get_event_store()
    op_store = get_operational_store()

    # Header counts — always based on all statuses so the panel is truthful
    # regardless of which status tab is selected.
    status_counts = await event_store.count_alerts_by_status(since=since)
    queued_count = status_counts.get("queued", 0)
    analyzing_count = status_counts.get("analyzing", 0)
    failed_count = status_counts.get("failed", 0)
    deferred_count = status_counts.get("deferred", 0)

    # Display rows — filtered by the selected status tab.
    status_filter = None if status == "all" else status
    alerts = await event_store.query_alerts(since=since, status=status_filter, limit=2000)

    grouped_rows = await _build_queue_rows(alerts, op_store)

    # Time-behind estimate based on actively queued alerts only (not deferred).
    _DEFAULT_LATENCY_S = 150
    estimated_s = queued_count * _DEFAULT_LATENCY_S
    h, rem = divmod(estimated_s, 3600)
    m = rem // 60
    if h > 0:
        time_behind: str | None = f"~{h}h {m}min behind" if m else f"~{h}h behind"
    elif m > 0:
        time_behind = f"~{m}min behind"
    else:
        time_behind = None

    return templates.TemplateResponse(request, "queue.html", {
        "rows": grouped_rows,
        "window": window,
        "status_filter": status,
        "queued_count": queued_count,
        "analyzing_count": analyzing_count,
        "failed_count": failed_count,
        "deferred_count": deferred_count,
        "time_behind": time_behind,
        "total": len(alerts),
    })


_STATUS_RANK = {"analyzed": 5, "analyzing": 4, "queued": 3, "failed": 2, "deferred": 1}


async def _build_queue_rows(alerts: list[dict], op_store) -> list[dict]:
    """Group alerts by (signature_id, src_ip, dst_ip) within a 1-hour window.

    Returns one row per group, sorted newest-first by ingest_timestamp, with
    verdict and count attached.

    Verdict bubbling: the triage worker processes oldest-first, but the group
    representative is the most-recently ingested. Without bubbling, a group of
    30 alerts whose first member is analyzed shows no verdict because the rep is
    still queued. The fix: use any analyzed member's verdict for the group, and
    link to that member so the analyst lands on the full investigation view.
    """
    # Collect verdict info per alert
    verdict_map: dict[str, dict] = {}
    for alert in alerts:
        vid = alert.get("verdict_id")
        if vid and vid not in verdict_map:
            v = await op_store.get_verdict(vid)
            if v:
                verdict_map[vid] = v

    # Group: key = (sig_id, src_ip, dst_ip, hour_bucket)
    # Bucket by ingest_timestamp so PCAP replays (with historical event_timestamps)
    # still group correctly by ingestion window.
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for alert in alerts:
        ts_str = alert.get("ingest_timestamp") or alert.get("event_timestamp", "")
        try:
            ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            bucket = ts.replace(minute=0, second=0, microsecond=0)
        except (ValueError, AttributeError):
            bucket = datetime.now(UTC).replace(minute=0, second=0, microsecond=0)

        key = (
            alert.get("signature_id"),
            alert.get("src_ip"),
            alert.get("dst_ip"),
            bucket,
        )
        groups[key].append(alert)

    rows = []
    for key, members in groups.items():
        # Metadata from the most-recently ingested member
        rep = max(members, key=lambda a: a.get("ingest_timestamp") or "")

        # Verdict: prefer any analyzed member over the representative.
        # The worker processes oldest-first; if rep is still queued the verdict
        # would be invisible without this bubbling.
        analyzed = [m for m in members if m.get("verdict_id")]
        if analyzed:
            verdict_member = max(analyzed, key=lambda a: a.get("ingest_timestamp") or "")
            verdict = verdict_map.get(verdict_member.get("verdict_id") or "")
            link_id = verdict_member["alert_id"]
        else:
            verdict = None
            link_id = rep["alert_id"]

        # Best status across the group (analyzed beats queued etc.)
        group_status = max(
            members, key=lambda a: _STATUS_RANK.get(a.get("status", ""), 0)
        ).get("status", "queued")

        rows.append({
            "alert_id": link_id,
            "count": len(members),
            "signature_msg": rep.get("signature_msg") or "Unknown signature",
            "signature_severity": rep.get("signature_severity"),
            "src_ip": rep.get("src_ip") or "?",
            "dst_ip": rep.get("dst_ip") or "?",
            "src_port": rep.get("src_port"),
            "dst_port": rep.get("dst_port"),
            "proto": rep.get("proto"),
            "app_proto": rep.get("app_proto"),
            "event_timestamp": rep.get("event_timestamp"),
            "ingest_timestamp": rep.get("ingest_timestamp"),
            "status": group_status,
            "verdict_category": verdict["verdict_category"] if verdict else None,
            "confidence_score": verdict["confidence_score"] if verdict else None,
            "disposition_id": rep.get("disposition_id"),
            "attacker_ip": rep.get("attacker_role"),
            "victim_ip": rep.get("victim_role"),
        })

    # Sort newest-first by ingest_timestamp (when alert arrived in our system).
    rows.sort(key=lambda r: r.get("ingest_timestamp") or "", reverse=True)
    return rows
