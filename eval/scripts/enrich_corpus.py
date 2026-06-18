# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""One-time script: inject simulated VT threat intel into eval_corpus.json.

For each corpus entry whose src_ip or dest_ip matches a known malicious IP
(from the pcap_iocs block already in the corpus), adds a threat_intel_context
list that simulates what VirusTotal enrichment would return in the real product.

Run from the project root:
    python eval/scripts/enrich_corpus.py
"""
from __future__ import annotations

import json
from pathlib import Path

CORPUS_PATH = Path("eval/data/eval_corpus.json")

# Simulated VT data for each malicious IP in the corpus.
# Values reflect realistic detection counts for these IPs in mid-2023.
VT_SIM: dict[str, dict] = {
    # RIG EK campaign
    "188.227.106.13": {
        "label": "RIG Exploit Kit server (June 2023 campaign)",
        "vt_malicious": 15,
        "vt_total": 90,
    },
    "62.204.41.175": {
        "label": "Malware loader / Redline Stealer C2 (RIG EK chain)",
        "vt_malicious": 20,
        "vt_total": 90,
    },
    # IcedID / Cobalt Strike campaign
    "206.166.251.62": {
        "label": "IcedID installer server (March 2023 campaign)",
        "vt_malicious": 20,
        "vt_total": 90,
    },
    "195.20.17.21": {
        "label": "IcedID C2 server (March 2023 campaign)",
        "vt_malicious": 18,
        "vt_total": 90,
    },
    "5.230.73.157": {
        "label": "IcedID C2 server (March 2023 campaign)",
        "vt_malicious": 17,
        "vt_total": 90,
    },
    "193.239.85.16": {
        "label": "BackConnect C2 server (IcedID post-exploitation)",
        "vt_malicious": 22,
        "vt_total": 90,
    },
    "31.220.50.207": {
        "label": "Cobalt Strike C2 server (IcedID post-exploitation)",
        "vt_malicious": 25,
        "vt_total": 90,
    },
}


def build_hit(ip: str) -> dict:
    sim = VT_SIM[ip]
    return {
        "indicator": ip,
        "type": "ip",
        "label": sim["label"],
        "vt_malicious": sim["vt_malicious"],
        "vt_total": sim["vt_total"],
        "source": "VirusTotal (eval-time simulation)",
    }


def main() -> None:
    data = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))

    # Collect all malicious IPs across every pcap_iocs entry.
    # Each campaign uses unique IPs, so no cross-contamination risk.
    all_malicious_ips: set[str] = set()
    for ioc in data.get("pcap_iocs", {}).values():
        all_malicious_ips.update(ioc.get("malicious_ips", []))

    updated = 0
    for entry in data["entries"]:
        malicious_ips = all_malicious_ips

        raw = entry.get("raw_eve", {})
        src_ip = raw.get("src_ip", "")
        dest_ip = raw.get("dest_ip", "")

        hits: list[dict] = []
        seen: set[str] = set()
        for ip in (src_ip, dest_ip):
            if ip in malicious_ips and ip in VT_SIM and ip not in seen:
                hits.append(build_hit(ip))
                seen.add(ip)

        if hits:
            entry["threat_intel_context"] = hits
            updated += 1
        elif "threat_intel_context" not in entry:
            entry["threat_intel_context"] = []

    CORPUS_PATH.write_text(
        json.dumps(data, indent=4, ensure_ascii=False),
        encoding="utf-8",
    )
    print(f"Done. Updated {updated}/{len(data['entries'])} entries with threat intel context.")


if __name__ == "__main__":
    main()
