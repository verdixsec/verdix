# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Correlated-context selection and partition for one alert (ADR-025).

Entry point: build_flow_context(alert, flow_events, delay_seconds) -> FlowContext

Pure functions, no I/O. The triage worker feeds it the rows EventStore returns
for the alert's flow_id; the eval corpus builder feeds it the same flow's lines
from eve.json. Both get identical selection and partition.

Selection:
  * Window: alert.flow.start <= event timestamp <= alert timestamp + delay,
    both ends inclusive. Timestamps are parsed to aware datetimes, so sensors
    logging a non-UTC offset compare correctly. With no flow.start there is no
    lower bound; when the alert timestamp parses, an event whose own timestamp
    does not parse is dropped.
  * The alert itself is excluded: the first event equal to the alert dict is
    removed. The alerts and eve_events tables store json.dumps of the same
    parsed dict, so the alert's own eve_events row decodes equal to it.
  * Order: parsed timestamp, then canonical JSON, so the result does not
    depend on input order.

Partition:
  * This transaction: DNS paired by message id + query name (case-insensitive),
    HTTP by tx_id. Suricata 8 tls events carry no tx_id, so TLS always uses the
    single-transaction rule. When the alert has no tx_id or app-layer block,
    the flow's only transaction of the alert's app_proto is used if there is
    exactly one; otherwise the section is empty and says why. alert_protocol
    is None when the alert's protocol produces no transaction records.
  * Other activity: every distinct co-alert (identical ones collapsed with a
    count), other DNS/HTTP/TLS names (capped, with an omitted count), flow
    records, and every other event type as-is.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

OTHER_NAME_CAP = 20
HTTP_LINES_PER_HOST = 5
_TX_PROTOS = ("dns", "http", "tls")

# transaction_status values
MATCHED = "matched"        # paired by DNS id + name or HTTP tx_id
SINGLE = "single"          # fallback: the flow's only transaction of that protocol
NO_DETAILS = "no_details"  # alert carries no transaction details, flow has several
NONE = "none"              # no transaction record inside the window


def parse_ts(value: Any) -> datetime | None:
    """Parse an EVE timestamp ("+0000" or "+00:00" offset) to an aware datetime."""
    if not isinstance(value, str) or not value:
        return None
    try:
        ts = datetime.fromisoformat(value)
    except ValueError:
        try:
            ts = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f%z")
        except ValueError:
            return None
    return ts if ts.tzinfo is not None else None


def dns_name(block: Any) -> str | None:
    """The query name of a dns block: queries[] (Suricata 8), query[] or flat rrname."""
    if not isinstance(block, dict):
        return None
    for key in ("queries", "query"):
        items = block.get(key) or []
        if isinstance(items, dict):
            items = [items]
        if isinstance(items, list) and items and isinstance(items[0], dict):
            name = items[0].get("rrname")
            if name:
                return str(name)
    name = block.get("rrname")
    return str(name) if name else None


@dataclass
class NameGroup:
    """One other name on the flow, with its summary lines."""

    event_type: str
    name: str
    lines: list[str]
    omitted: int = 0  # HTTP only: distinct requests to this host beyond the cap


@dataclass
class CoAlert:
    """A distinct co-alert and how many identical copies the window holds."""

    event: dict[str, Any]
    count: int = 1


@dataclass
class FlowContext:
    selected: list[dict[str, Any]]
    transaction: list[dict[str, Any]] = field(default_factory=list)
    transaction_status: str = NONE
    co_alerts: list[CoAlert] = field(default_factory=list)
    names: list[NameGroup] = field(default_factory=list)
    names_omitted: int = 0
    flows: list[dict[str, Any]] = field(default_factory=list)
    other: list[dict[str, Any]] = field(default_factory=list)
    # The alert's transaction protocol (dns, http or tls), or None when its
    # protocol produces no transaction records (raw TCP, app_proto failed/absent).
    alert_protocol: str | None = None

    @property
    def has_other_activity(self) -> bool:
        return bool(self.co_alerts or self.names or self.flows or self.other)


def _sort_key(event: dict[str, Any]) -> tuple[float, str]:
    ts = parse_ts(event.get("timestamp"))
    return (
        ts.timestamp() if ts else float("inf"),
        json.dumps(event, sort_keys=True, default=str),
    )


def select_events(
    alert: dict[str, Any],
    flow_events: list[dict[str, Any]],
    delay_seconds: float,
) -> list[dict[str, Any]]:
    """Bound flow_events to [flow.start, alert ts + delay], drop the alert, sort."""
    alert_ts = parse_ts(alert.get("timestamp"))
    until = alert_ts + timedelta(seconds=delay_seconds) if alert_ts else None
    flow_block = alert.get("flow")
    since = parse_ts(flow_block.get("start")) if isinstance(flow_block, dict) else None

    selected: list[dict[str, Any]] = []
    removed_self = False
    for event in flow_events:
        if not removed_self and event == alert:
            removed_self = True
            continue
        ts = parse_ts(event.get("timestamp"))
        if until is not None and (ts is None or ts > until):
            continue
        if since is not None and ts is not None and ts < since:
            continue
        selected.append(event)
    return sorted(selected, key=_sort_key)


def _event_name(event: dict[str, Any]) -> str | None:
    etype = event.get("event_type")
    if etype == "dns":
        return dns_name(event.get("dns"))
    if etype == "http":
        name = (event.get("http") or {}).get("hostname")
    elif etype == "tls":
        tls = event.get("tls") or {}
        name = tls.get("sni") or tls.get("subject")
    else:
        return None
    return str(name) if name else None


def _dns_tx(event: dict[str, Any]) -> tuple[Any, str] | None:
    block = event.get("dns") or {}
    name = dns_name(block)
    if not isinstance(block, dict) or block.get("id") is None or not name:
        return None
    return (block.get("id"), name.lower())


def _alert_proto(alert: dict[str, Any]) -> tuple[str | None, bool]:
    """(protocol, alert carries that protocol's app-layer block)."""
    for proto in _TX_PROTOS:
        if alert.get(proto):
            return proto, True
    app_proto = alert.get("app_proto")
    return (app_proto, False) if app_proto in _TX_PROTOS else (None, False)


def _tx_identity(proto: str, event: dict[str, Any]) -> Any:
    if proto == "dns":
        return _dns_tx(event)
    if proto == "http":
        return event.get("tx_id")
    return "tls"  # Suricata 8 tls events carry no tx_id: one handshake per flow


def _match_transaction(
    alert: dict[str, Any], events: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], str]:
    proto, has_block = _alert_proto(alert)
    if proto is None:
        return [], NONE
    candidates = [e for e in events if e.get("event_type") == proto]
    if has_block:
        if proto == "dns":
            want = _dns_tx(alert)
            if want is not None:
                tx = [e for e in candidates if _dns_tx(e) == want]
                return tx, MATCHED if tx else NONE
        elif proto == "http" and alert.get("tx_id") is not None:
            tx = [e for e in candidates if e.get("tx_id") == alert.get("tx_id")]
            return tx, MATCHED if tx else NONE
    # No pairable transaction details on the alert (always the case for TLS).
    identities = {
        json.dumps(_tx_identity(proto, e), default=str)
        for e in candidates
        if _tx_identity(proto, e) is not None
    }
    if len(identities) == 1:
        return [e for e in candidates if _tx_identity(proto, e) is not None], SINGLE
    # TLS with a block: nothing pairable is missing from the alert, the
    # handshake record is simply not in the window.
    if has_block and proto == "tls":
        return [], NONE
    return [], NO_DETAILS


def _http_line(block: dict[str, Any]) -> str:
    line = (
        f"{block.get('http_method')} {block.get('hostname')}{block.get('url')}"
        f" ({block.get('status')})"
    )
    ua = block.get("http_user_agent")
    return line + (f' UA="{ua}"' if ua else "")


def _summarise(etype: str, events: list[dict[str, Any]]) -> tuple[list[str], int]:
    """Summary lines for one name group, and how many HTTP lines were cut."""
    if etype == "dns":
        rrtypes: list[str] = []
        answers: list[str] = []
        rcodes: list[str] = []
        for event in events:
            block = event.get("dns") or {}
            queries = block.get("queries") or block.get("query") or []
            if isinstance(queries, dict):
                queries = [queries]
            for q in queries if isinstance(queries, list) else []:
                rrtype = q.get("rrtype") if isinstance(q, dict) else None
                if rrtype and rrtype not in rrtypes:
                    rrtypes.append(str(rrtype))
            if block.get("rrtype") and block["rrtype"] not in rrtypes:
                rrtypes.append(str(block["rrtype"]))
            for ans in block.get("answers") or []:
                rdata = ans.get("rdata") if isinstance(ans, dict) else None
                if rdata and str(rdata) not in answers:
                    answers.append(str(rdata))
            rcode = block.get("rcode")
            if block.get("type") == "response" and rcode and rcode not in rcodes:
                rcodes.append(str(rcode))
        line = f" {'/'.join(rrtypes)}" if rrtypes else ""
        line += f" -> {', '.join(answers)}" if answers else ""
        line += f" [{', '.join(rcodes)}]" if rcodes else ""
        line += f", {len(events)} record{'s' if len(events) != 1 else ''}"
        return [line], 0
    if etype == "http":
        lines: list[str] = []
        for event in events:
            line = _http_line(event.get("http") or {})
            if line not in lines:
                lines.append(line)
        return lines[:HTTP_LINES_PER_HOST], max(0, len(lines) - HTTP_LINES_PER_HOST)
    lines = []
    for event in events:
        tls = event.get("tls") or {}
        line = f"SNI={tls.get('sni')} subject={tls.get('subject')}"
        if line not in lines:
            lines.append(line)
    return lines, 0


def _co_alert_key(event: dict[str, Any]) -> tuple[Any, ...]:
    block = event.get("alert") or {}
    return (
        block.get("signature_id"),
        block.get("signature"),
        block.get("category"),
        block.get("severity"),
    )


def build_flow_context(
    alert: dict[str, Any],
    flow_events: list[dict[str, Any]],
    delay_seconds: float = 30.0,
    *,
    name_cap: int = OTHER_NAME_CAP,
) -> FlowContext:
    """Select the alert's correlated context and split it into the two sections."""
    selected = select_events(alert, flow_events, delay_seconds)
    transaction, status = _match_transaction(alert, selected)
    in_transaction = {id(e) for e in transaction}
    ctx = FlowContext(
        selected=selected,
        transaction=transaction,
        transaction_status=status,
        alert_protocol=_alert_proto(alert)[0],
    )

    co_alert_index: dict[tuple[Any, ...], CoAlert] = {}
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for event in selected:
        if id(event) in in_transaction:
            continue
        etype = event.get("event_type")
        name = _event_name(event) if etype in _TX_PROTOS else None
        if etype == "alert":
            key = _co_alert_key(event)
            if key in co_alert_index:
                co_alert_index[key].count += 1
            else:
                co_alert_index[key] = CoAlert(event)
                ctx.co_alerts.append(co_alert_index[key])
        elif etype == "flow":
            ctx.flows.append(event)
        elif name:
            groups.setdefault((str(etype), name.lower()), []).append(event)
        else:
            ctx.other.append(event)

    keys = list(groups)
    for etype, lowered in keys[:name_cap]:
        events = groups[(etype, lowered)]
        lines, omitted = _summarise(etype, events)
        ctx.names.append(NameGroup(etype, _event_name(events[0]) or lowered, lines, omitted))
    ctx.names_omitted = max(0, len(keys) - name_cap)
    return ctx
