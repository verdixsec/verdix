# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""In-memory pipeline models for the EVE ingestion pipeline.

These are the typed Python objects flowing through async queues between the
tailer, broadcaster, indexer, and dispatcher. Distinct from the SQLAlchemy
ORM models in src/infra/db/models.py which represent database row shapes.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class EventType(StrEnum):
    """Known EVE event_type values. UNKNOWN is the catch-all for unrecognised types.

    Covers all standard and advanced types up to Suricata 7.x / 9.0-dev.
    New types added by future Suricata versions safely map to UNKNOWN.
    """

    # Core system & security
    ALERT = "alert"
    ANOMALY = "anomaly"
    DROP = "drop"
    ENGINE = "engine"
    FILEINFO = "fileinfo"
    FLOW = "flow"
    NETFLOW = "netflow"
    PKTHDR = "pkthdr"
    STATS = "stats"

    # Application layer — web
    HTTP = "http"
    HTTP2 = "http2"
    MQTT = "mqtt"

    # Application layer — email
    IMAP = "imap"
    POP3 = "pop3"
    SMTP = "smtp"

    # Application layer — remote access
    RDP = "rdp"
    RFB = "rfb"
    SSH = "ssh"

    # Application layer — encryption / auth
    IKE = "ike"
    KRB5 = "krb5"
    QUIC = "quic"
    TLS = "tls"

    # Application layer — infrastructure
    DHCP = "dhcp"
    DNS = "dns"
    NTP = "ntp"
    SNMP = "snmp"
    TFTP = "tftp"

    # Application layer — file transfer
    FTP = "ftp"
    FTP_DATA = "ftp_data"
    NFS = "nfs"
    SMB = "smb"

    # Application layer — database
    PGSQL = "pgsql"

    # Application layer — industrial (ICS/SCADA)
    DNP3 = "dnp3"
    ENIP = "enip"
    MODBUS = "modbus"

    # Application layer — P2P / other
    BITTORRENT_DHT = "bittorrent_dht"
    SIP = "sip"

    # Network layer
    ARP = "arp"
    ETHER = "ether"
    FRAME = "frame"

    # Catch-all for types added in future Suricata versions
    UNKNOWN = "unknown"

    @classmethod
    def from_str(cls, value: str) -> EventType:
        try:
            return cls(value)
        except ValueError:
            return cls.UNKNOWN


@dataclass
class EveEvent:
    """Parsed EVE JSON event flowing through the ingestion pipeline.

    Constructed by the tailer; consumed by the indexer (all types) and the
    dispatcher (alert types only). Carries the full raw dict for storage.
    """

    event_type: EventType
    flow_id: int | None
    timestamp: str          # ISO-8601 string directly from EVE
    raw: dict[str, Any]     # full parsed EVE JSON — stored as-is

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EveEvent:
        """Construct an EveEvent from a parsed EVE JSON dict."""
        return cls(
            event_type=EventType.from_str(data.get("event_type", "")),
            flow_id=data.get("flow_id"),
            timestamp=data.get("timestamp", ""),
            raw=data,
        )

    @property
    def is_alert(self) -> bool:
        return self.event_type == EventType.ALERT
