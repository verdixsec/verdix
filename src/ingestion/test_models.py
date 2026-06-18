# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Tests for ingestion pipeline models (EveEvent, EventType)."""
from __future__ import annotations

from src.ingestion.models import EveEvent, EventType

# ---------------------------------------------------------------------------
# EventType
# ---------------------------------------------------------------------------


def test_event_type_core() -> None:
    assert EventType.from_str("alert") == EventType.ALERT
    assert EventType.from_str("anomaly") == EventType.ANOMALY
    assert EventType.from_str("drop") == EventType.DROP
    assert EventType.from_str("engine") == EventType.ENGINE
    assert EventType.from_str("fileinfo") == EventType.FILEINFO
    assert EventType.from_str("flow") == EventType.FLOW
    assert EventType.from_str("netflow") == EventType.NETFLOW
    assert EventType.from_str("stats") == EventType.STATS


def test_event_type_application_layer() -> None:
    # web
    assert EventType.from_str("http") == EventType.HTTP
    assert EventType.from_str("http2") == EventType.HTTP2
    assert EventType.from_str("mqtt") == EventType.MQTT
    # email
    assert EventType.from_str("smtp") == EventType.SMTP
    assert EventType.from_str("imap") == EventType.IMAP
    assert EventType.from_str("pop3") == EventType.POP3
    # remote access
    assert EventType.from_str("ssh") == EventType.SSH
    assert EventType.from_str("rdp") == EventType.RDP
    assert EventType.from_str("rfb") == EventType.RFB
    # encryption / auth
    assert EventType.from_str("tls") == EventType.TLS
    assert EventType.from_str("quic") == EventType.QUIC
    assert EventType.from_str("krb5") == EventType.KRB5
    assert EventType.from_str("ike") == EventType.IKE
    # infrastructure
    assert EventType.from_str("dns") == EventType.DNS
    assert EventType.from_str("dhcp") == EventType.DHCP
    assert EventType.from_str("ntp") == EventType.NTP
    assert EventType.from_str("snmp") == EventType.SNMP
    assert EventType.from_str("tftp") == EventType.TFTP
    # file transfer
    assert EventType.from_str("ftp") == EventType.FTP
    assert EventType.from_str("ftp_data") == EventType.FTP_DATA
    assert EventType.from_str("smb") == EventType.SMB
    assert EventType.from_str("nfs") == EventType.NFS
    # database
    assert EventType.from_str("pgsql") == EventType.PGSQL
    # industrial
    assert EventType.from_str("modbus") == EventType.MODBUS
    assert EventType.from_str("dnp3") == EventType.DNP3
    assert EventType.from_str("enip") == EventType.ENIP
    # P2P / other
    assert EventType.from_str("bittorrent_dht") == EventType.BITTORRENT_DHT
    assert EventType.from_str("sip") == EventType.SIP


def test_event_type_network_layer() -> None:
    assert EventType.from_str("arp") == EventType.ARP
    assert EventType.from_str("ether") == EventType.ETHER
    assert EventType.from_str("frame") == EventType.FRAME


def test_event_type_unknown_falls_back() -> None:
    assert EventType.from_str("something_new") == EventType.UNKNOWN
    assert EventType.from_str("") == EventType.UNKNOWN


def test_event_type_is_str_subclass() -> None:
    assert EventType.ALERT == "alert"
    assert EventType.DNS == "dns"


# ---------------------------------------------------------------------------
# EveEvent.from_dict
# ---------------------------------------------------------------------------


def _alert_dict() -> dict:
    return {
        "timestamp": "2026-05-09T12:00:00.000000+0000",
        "flow_id": 12345,
        "event_type": "alert",
        "src_ip": "10.0.0.1",
        "dest_ip": "8.8.8.8",
        "alert": {"signature_id": 2000001, "severity": 1},
    }


def test_from_dict_alert() -> None:
    event = EveEvent.from_dict(_alert_dict())
    assert event.event_type == EventType.ALERT
    assert event.flow_id == 12345
    assert event.timestamp == "2026-05-09T12:00:00.000000+0000"
    assert event.raw["src_ip"] == "10.0.0.1"


def test_from_dict_dns() -> None:
    data = {
        "timestamp": "2026-05-09T12:01:00.000000+0000",
        "flow_id": 99,
        "event_type": "dns",
        "dns": {"rrname": "example.com"},
    }
    event = EveEvent.from_dict(data)
    assert event.event_type == EventType.DNS
    assert event.flow_id == 99


def test_from_dict_missing_flow_id() -> None:
    data = {"timestamp": "2026-05-09T12:00:00+0000", "event_type": "stats"}
    event = EveEvent.from_dict(data)
    assert event.flow_id is None
    assert event.event_type == EventType.STATS


def test_from_dict_unknown_event_type() -> None:
    data = {"timestamp": "2026-05-09T12:00:00+0000", "event_type": "future_type", "flow_id": 1}
    event = EveEvent.from_dict(data)
    assert event.event_type == EventType.UNKNOWN


def test_from_dict_missing_timestamp_defaults_to_empty_string() -> None:
    data = {"event_type": "flow", "flow_id": 1}
    event = EveEvent.from_dict(data)
    assert event.timestamp == ""


# ---------------------------------------------------------------------------
# EveEvent.is_alert
# ---------------------------------------------------------------------------


def test_is_alert_true_for_alert_type() -> None:
    event = EveEvent.from_dict(_alert_dict())
    assert event.is_alert is True


def test_is_alert_false_for_non_alert() -> None:
    data = {"timestamp": "2026-05-09T12:00:00+0000", "flow_id": 1, "event_type": "dns"}
    event = EveEvent.from_dict(data)
    assert event.is_alert is False


# ---------------------------------------------------------------------------
# raw dict identity (no copy — pipeline efficiency)
# ---------------------------------------------------------------------------


def test_raw_is_same_object_as_input_dict() -> None:
    data = _alert_dict()
    event = EveEvent.from_dict(data)
    assert event.raw is data
