# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Tests for the correlated-context selection and partition (ADR-025)."""
from __future__ import annotations

import copy
import json
import random
from datetime import datetime, timedelta
from typing import Any

from src.domain.flow_context import (
    HTTP_LINES_PER_HOST,
    MATCHED,
    NO_DETAILS,
    NONE,
    SINGLE,
    build_flow_context,
    parse_ts,
    select_events,
)

FLOW_ID = 1111
T0 = datetime.fromisoformat("2026-11-09T10:00:00.000000+00:00")


def _ts(seconds: float, offset: str = "+0000") -> str:
    """Suricata-style timestamp, seconds after T0, rendered in the given offset."""
    tz = datetime.strptime(offset, "%z").tzinfo
    return (T0 + timedelta(seconds=seconds)).astimezone(tz).strftime(
        "%Y-%m-%dT%H:%M:%S.%f%z"
    )


def _base(event_type: str, seconds: float, **extra: Any) -> dict[str, Any]:
    ev: dict[str, Any] = {
        "timestamp": _ts(seconds),
        "flow_id": FLOW_ID,
        "event_type": event_type,
        "src_ip": "10.0.0.5",
        "src_port": 50000,
        "dest_ip": "203.0.113.10",
        "dest_port": 80,
        "proto": "TCP",
    }
    ev.update(extra)
    return ev


def _http(seconds: float, tx_id: int, url: str = "/", host: str = "c2.example.net",
          ua: str | None = "Mozilla/5.0", method: str = "GET") -> dict[str, Any]:
    block: dict[str, Any] = {"hostname": host, "url": url, "http_method": method, "status": 200}
    if ua:
        block["http_user_agent"] = ua
    return _base("http", seconds, tx_id=tx_id, http=block)


def _dns(seconds: float, kind: str, msg_id: int, name: str, tx_id: int,
         rdata: str | None = None) -> dict[str, Any]:
    block: dict[str, Any] = {
        "version": 3, "type": kind, "tx_id": tx_id, "id": msg_id,
        "queries": [{"rrname": name, "rrtype": "A"}],
    }
    if kind == "response":
        block["rcode"] = "NOERROR"
        if rdata:
            block["answers"] = [{"rrname": name, "rrtype": "A", "rdata": rdata}]
    return _base("dns", seconds, dest_port=53, proto="UDP", dns=block)


def _tls(seconds: float, sni: str = "c2.example.net") -> dict[str, Any]:
    return _base("tls", seconds, dest_port=443, tls={"sni": sni, "subject": f"CN={sni}"})


def _alert(seconds: float = 0, sid: int = 2000001, sig: str = "ET MALWARE Test",
           flow_start: float | None = -5, **extra: Any) -> dict[str, Any]:
    ev = _base("alert", seconds, alert={
        "signature_id": sid, "signature": sig,
        "category": "A Network Trojan was Detected", "severity": 1,
    })
    if flow_start is not None:
        ev["flow"] = {"start": _ts(flow_start), "pkts_toserver": 3}
    ev.update(extra)
    return ev


def _flow_record(seconds: float) -> dict[str, Any]:
    return _base("flow", seconds, flow={"bytes_toserver": 100, "bytes_toclient": 200})


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------


def test_parse_ts_accepts_both_offset_spellings() -> None:
    assert parse_ts("2026-11-09T10:00:00.000000+0000") == T0
    assert parse_ts("2026-11-09T10:00:00+00:00") == T0
    assert parse_ts("not a time") is None
    assert parse_ts(None) is None


def test_self_exclusion_drops_one_equal_copy_only() -> None:
    alert = _alert(http={"hostname": "c2.example.net"}, tx_id=0, app_proto="http")
    stored_copy = json.loads(json.dumps(alert))  # what the eve_events row decodes to
    duplicate = json.loads(json.dumps(alert))
    selected = select_events(alert, [stored_copy, duplicate, _http(1, 0)], 30)
    assert selected.count(alert) == 1
    assert len(selected) == 2


def test_self_exclusion_removes_nothing_without_a_match() -> None:
    alert = _alert()
    other = _alert(seconds=1, sid=2000002)
    assert select_events(alert, [other], 30) == [other]


def test_until_bound_is_inclusive_and_excludes_later_events() -> None:
    alert = _alert()
    at_bound = _http(30, 1)
    after = _http(30.001, 2)
    selected = select_events(alert, [at_bound, after], 30)
    assert selected == [at_bound]


def test_until_bound_follows_configured_delay() -> None:
    alert = _alert()
    ev = _http(45, 1)
    assert select_events(alert, [ev], 30) == []
    assert select_events(alert, [ev], 60) == [ev]


def test_event_without_parseable_timestamp_is_dropped() -> None:
    alert = _alert()
    ev = _http(1, 1)
    ev["timestamp"] = "garbage"
    assert select_events(alert, [ev], 30) == []


def test_since_bound_is_flow_start() -> None:
    alert = _alert(flow_start=-5)
    before = _http(-6, 1)
    at_start = _http(-5, 2)
    assert select_events(alert, [before, at_start], 30) == [at_start]


def test_no_flow_start_means_no_lower_bound() -> None:
    alert = _alert(flow_start=None)
    early = _http(-3600, 1)
    assert select_events(alert, [early], 30) == [early]


def test_non_utc_sensor_offsets_compare_by_instant() -> None:
    alert = _alert()
    alert["timestamp"] = _ts(0, "-0500")
    inside = _http(20, 1)
    inside["timestamp"] = _ts(20, "+0200")
    outside = _http(40, 2)
    outside["timestamp"] = _ts(40, "-0500")
    assert select_events(alert, [inside, outside], 30) == [inside]


def test_order_is_deterministic_whatever_the_input_order() -> None:
    alert = _alert(http={"hostname": "c2.example.net"}, tx_id=3, app_proto="http")
    events = [_http(i % 4, i, url=f"/{i}") for i in range(12)] + [
        _dns(1, "request", 7, "a.example.org", 0),
        _alert(seconds=1, sid=2000002),
        _flow_record(2),
    ]
    ref = build_flow_context(alert, events, 30)
    for seed in range(5):
        shuffled = copy.deepcopy(events)
        random.Random(seed).shuffle(shuffled)
        ctx = build_flow_context(alert, shuffled, 30)
        assert ctx.selected == ref.selected
        assert ctx.transaction == ref.transaction
        assert [n.lines for n in ctx.names] == [n.lines for n in ref.names]
    ts = [parse_ts(e["timestamp"]) for e in ref.selected]
    assert all(t is not None for t in ts)
    assert ts == sorted(t for t in ts if t is not None)


# ---------------------------------------------------------------------------
# This transaction
# ---------------------------------------------------------------------------


def test_dns_pairs_request_and_response_by_message_id_and_name() -> None:
    req = _dns(0, "request", 4242, "evil.example.com", 0)
    resp = _dns(0.1, "response", 4242, "evil.example.com", 1, rdata="198.51.100.7")
    retry_other_id = _dns(1, "request", 999, "evil.example.com", 2)
    other_name = _dns(1, "request", 4242, "other.example.com", 3)
    alert = _alert(app_proto="dns", tx_id=0, dns=copy.deepcopy(req["dns"]))
    alert["dns"]["queries"][0]["rrname"] = "EVIL.example.com"  # case-insensitive
    ctx = build_flow_context(alert, [req, resp, retry_other_id, other_name], 30)
    assert ctx.transaction_status == MATCHED
    assert ctx.transaction == [req, resp]
    names = {(g.event_type, g.name) for g in ctx.names}
    assert names == {("dns", "evil.example.com"), ("dns", "other.example.com")}


def test_http_pairs_by_tx_id_and_siblings_go_to_other_activity() -> None:
    mine = _http(0, 1, url="/gate.php", method="POST")
    siblings = [_http(1, 0, url="/a"), _http(2, 2, url="/b")]
    alert = _alert(app_proto="http", tx_id=1, http={"hostname": "c2.example.net"})
    ctx = build_flow_context(alert, [*siblings, mine], 30)
    assert ctx.transaction_status == MATCHED
    assert ctx.transaction == [mine]
    assert len(ctx.names) == 1
    assert ctx.names[0].lines == [
        'GET c2.example.net/a (200) UA="Mozilla/5.0"',
        'GET c2.example.net/b (200) UA="Mozilla/5.0"',
    ]


def test_http_tx_id_outside_window_reports_none() -> None:
    alert = _alert(app_proto="http", tx_id=5, http={"hostname": "c2.example.net"})
    late = _http(200, 5)
    ctx = build_flow_context(alert, [late], 30)
    assert ctx.transaction == []
    assert ctx.transaction_status == NONE


def test_tls_uses_single_handshake_rule() -> None:
    hs = _tls(0.5)
    alert = _alert(app_proto="tls", tls={"sni": "c2.example.net"})
    ctx = build_flow_context(alert, [hs], 30)
    assert ctx.transaction_status == SINGLE
    assert ctx.transaction == [hs]
    assert ctx.names == []


def test_no_tx_details_with_one_transaction_uses_it() -> None:
    # phantom-001 shape: no tx_id, no http block, app_proto http.
    only = _http(1, 0)
    alert = _alert(app_proto="http")
    ctx = build_flow_context(alert, [only], 30)
    assert ctx.transaction_status == SINGLE
    assert ctx.transaction == [only]


def test_no_tx_details_with_several_transactions_leaves_section_empty() -> None:
    # redline-003 shape: no tx_id, no http block, four http transactions.
    txs = [_http(i, i, url=f"/{i}") for i in range(4)]
    alert = _alert(app_proto="http")
    ctx = build_flow_context(alert, txs, 30)
    assert ctx.transaction_status == NO_DETAILS
    assert ctx.transaction == []
    assert sum(len(g.lines) for g in ctx.names) == 4


def test_alert_protocol_reports_transaction_protocol() -> None:
    assert build_flow_context(_alert(app_proto="failed"), [], 30).alert_protocol is None
    assert build_flow_context(_alert(), [], 30).alert_protocol is None
    assert build_flow_context(_alert(app_proto="smb"), [], 30).alert_protocol is None
    assert build_flow_context(_alert(app_proto="dns"), [], 30).alert_protocol == "dns"
    tls = _alert(app_proto="tls", tls={"sni": "c2.example.net"})
    assert build_flow_context(tls, [], 30).alert_protocol == "tls"


def test_alert_without_app_layer_has_no_transaction() -> None:
    alert = _alert(app_proto="failed")
    ctx = build_flow_context(alert, [_flow_record(1)], 30)
    assert ctx.transaction_status == NONE
    assert len(ctx.flows) == 1


# ---------------------------------------------------------------------------
# Other activity
# ---------------------------------------------------------------------------


def test_identical_co_alerts_collapse_with_count_and_distinct_ones_stay() -> None:
    alert = _alert(app_proto="http", tx_id=0, http={"hostname": "c2.example.net"})
    beacons = [_alert(seconds=i, sid=2052099, sig="ET MALWARE Tasking") for i in range(1, 5)]
    other = _alert(seconds=2, sid=2000003, sig="ET INFO Other")
    ctx = build_flow_context(alert, [*beacons, other], 30)
    by_sid = {c.event["alert"]["signature_id"]: c.count for c in ctx.co_alerts}
    assert by_sid == {2052099: 4, 2000003: 1}


def test_other_names_capped_with_omitted_count() -> None:
    alert = _alert(app_proto="dns", dns={"id": 1, "queries": [{"rrname": "own.example"}]})
    events = [_dns(i * 0.1, "request", 100 + i, f"name{i:02d}.example.org", i) for i in range(25)]
    ctx = build_flow_context(alert, events, 30)
    assert len(ctx.names) == 20
    assert ctx.names_omitted == 5
    assert ctx.names[0].name == "name00.example.org"  # first appearance order


def test_dns_name_collapses_to_one_line() -> None:
    alert = _alert(app_proto="http", tx_id=0, http={"hostname": "x"})
    req = _dns(0, "request", 7, "a.example.org", 0)
    resp = _dns(0.1, "response", 7, "a.example.org", 1, rdata="198.51.100.1")
    ctx = build_flow_context(alert, [req, resp], 30)
    assert len(ctx.names) == 1
    assert ctx.names[0].lines == [" A -> 198.51.100.1 [NOERROR], 2 records"]


def test_http_capped_per_host_with_more_count() -> None:
    alert = _alert(app_proto="http", tx_id=99, http={"hostname": "c2.example.net"})
    events = [_http(i * 0.1, i, url=f"/p{i}") for i in range(HTTP_LINES_PER_HOST + 3)]
    ctx = build_flow_context(alert, events, 30)
    group = ctx.names[0]
    assert len(group.lines) == HTTP_LINES_PER_HOST
    assert group.omitted == 3


def test_flow_records_and_other_types_kept() -> None:
    alert = _alert(app_proto="http", tx_id=0, http={"hostname": "c2.example.net"})
    fileinfo = _base("fileinfo", 1, fileinfo={"filename": "/a"})
    ctx = build_flow_context(alert, [_flow_record(2), fileinfo], 30)
    assert len(ctx.flows) == 1
    assert ctx.other == [fileinfo]
    assert ctx.has_other_activity


def test_empty_flow() -> None:
    ctx = build_flow_context(_alert(app_proto="http"), [], 30)
    assert ctx.selected == []
    assert ctx.transaction_status == NO_DETAILS
    assert not ctx.has_other_activity
