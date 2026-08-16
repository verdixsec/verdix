<div align="center">

# Verdix

**Open-source AI triage for Suricata alerts — running entirely on your hardware.**

<!-- Screenshot: queue view showing analyzed alerts with TP/FP/suspicious verdicts -->
<!-- Add: docs/images/queue.png -->

[![Status: Early Access](https://img.shields.io/badge/status-Early%20Access-orange)](https://github.com/verdixsec/verdix)
[![Version: v0.1.5](https://img.shields.io/badge/version-v0.1.5-blue)](https://github.com/verdixsec/verdix/releases/tag/v0.1.5)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)

</div>

---

Your Suricata generates hundreds of EVE alerts a day. Most are false positives, but deciding which ones matter requires reading the rule grammar, correlating the surrounding flow records, enriching the indicators, and making a judgment call on every alert, every shift. Verdix does that work alongside you.

It drops in next to your existing Suricata installation via Docker. It reads your `eve.json` in real time, analyzes each alert, and produces a verdict with the full evidence chain attached. Your Suricata keeps running exactly as it was. Your SIEM keeps getting the same alerts. Nothing changes in your existing workflow. You have a second opinion on every alert.

**The AI runs in Docker on your own hardware. No payload data leaves the host.**

---

## How it works

For each Suricata alert, Verdix:

1. Reads all related `eve.json` records from the same network flow: the flow record, DNS queries, HTTP requests, TLS handshakes, and file events correlated by `flow_id`
2. Enriches the indicators: country and ASN from an embedded database (no internet required), internal hostnames via reverse DNS for your `HOME_NET` addresses, domain registration age and registrar via RDAP, and reputation via VirusTotal if you provide a free API key
3. Reads your `suricata.yaml` to understand your `HOME_NET` and assigns attacker/victim roles using the rule's direction, replacing Suricata's ambiguous src/dst with labels that actually mean something
4. Passes everything to a local LLM (Gemma 4, running in the sibling Docker container) which explains what the rule detected, what is actually happening in this specific alert, and recommends a verdict: *likely false positive*, *suspicious — investigate*, or *likely true positive*
5. Shows you the verdict with every piece of evidence it used: correlated records, enrichment results, rule explanation, role assignment, and a per-source ledger showing exactly what contributed and what was unavailable

You accept the verdict or override it. Verdix never takes action on an alert autonomously.

---

## Requirements

| | |
|---|---|
| **Hardware** | 32 GB RAM · 16 CPU cores · 60 GB free disk space |
| **GPU** | Not required. If present, Ollama uses it automatically, reducing verdict time from ~2 min to ~30 sec |
| **Software** | Docker 24+ with the `docker compose` plugin · Suricata running and producing `eve.json` |
| **OS** | Any Linux distribution that supports Docker 24+ (Ubuntu, Debian, RHEL, Rocky Linux, AlmaLinux, Fedora, openSUSE, and others) |
| **Network** | Outbound HTTPS required for RDAP domain lookups · optional but recommended for VirusTotal · GeoIP works fully offline |

**Fewer than 16 cores?** Verdix still runs, but verdict throughput drops below what a typical deployment generates and the queue falls behind. Verdix reports queue depth when this happens. It is not a configuration we recommend.

Disk space splits across two locations: Docker's image store and the model volume. See the [Deployment Guide](docs/DEPLOYMENT.md#before-you-begin) for the breakdown and what to do if you relocate Docker storage.

---

## Install

Verdix runs as two Docker containers alongside your existing Suricata. Install is `docker compose up` once `.env` points at your `eve.json` and `suricata.yaml` directories. First run pulls ~22 GB and takes 10–20 minutes.

See the [Deployment Guide](docs/DEPLOYMENT.md) for same-host, NFS, and SMB topologies, Docker installation, and storage sizing. Full configuration reference: [`example.env`](example.env).

---

## Your first verdict

The queue shows alerts as they arrive from `eve.json`. Each alert is analyzed automatically. Expect about 2 minutes per alert on 16-core CPU-only hardware, or ~30 seconds if a GPU is present.

To generate test traffic right now, run this on the Suricata host:
```bash
curl http://testmynids.org/uid/index.html
```
This fires the `ET ATTACK_RESPONSE Id Check Returned User Id` rule and produces an alert within seconds. See [Testing with Sample Traffic](docs/DEPLOYMENT.md#testing-with-sample-traffic) for more realistic test traffic, including malware PCAPs.

If something doesn't work, see the [Deployment Guide — Troubleshooting](docs/DEPLOYMENT.md#troubleshooting) section.

<!-- Screenshot: per-alert investigation view showing verdict, enrichment ledger, and evidence chain -->
<!-- Add: docs/images/alert.png -->

---

## Accuracy

Before writing any product code, we built an independent evaluation harness and assembled a labeled corpus of real Suricata alerts. The numbers below are its output, not our estimates.

| Metric | Result |
|---|---|
| Verdict accuracy | **79.2%** |
| False-negative rate | **0.0%** |
| Structured output reliability | **100%** |

The corpus holds 327 alerts, each labeled with a ground-truth verdict by an experienced analyst. We split it into a 274-alert development set and a 53-alert held-out test set along source boundaries, so no alert family appears in both; the held-out alerts come from sources the prompt was never tuned against. Accuracy was 79.2% on the held-out set and the same on the development set. Every verdict ran at temperature 0 (greedy decoding), so the score is deterministic and reproduces run to run. VirusTotal reputation, RDAP domain registration, and GeoIP enrichment ran on every entry, matching the production pipeline.

The corpus is built from malware PCAPs replayed through Emerging Threats Open rules, plus benign traffic from three sources: IoT-23 (a labeled academic honeypot-capture dataset), a capture of a personal host, and scripted traffic that trips Emerging Threats rules without being malicious. It covers the categories Suricata sensors actually fire on: infostealers, RATs, loaders, and C2 frameworks (Lumma, AsyncRAT, AgentTesla, Remcos, RedLine, Cobalt Strike, and others).

**0.0% false-negative rate.** No confirmed true positive was classified as a false positive anywhere in the 327-alert corpus. The target is ≤5%; zero is the strongest possible result. Missing a real threat is the worst outcome for a security tool, so this is the number we watch most closely.

All verdicts were generated by `gemma4:e4b-it-q8_0` (Google's Gemma 4, running locally inside Docker via Ollama). No alert data left the evaluation machine.

The evaluation harness ships in this repository under `eval/` and can be run against your own labeled corpus.

---

## This is early access

Verdix v0.1 is Early Access. It does one thing well: triage individual Suricata alerts with a local LLM and show you the evidence. Use it alongside your existing workflow, not instead of it.

**Working well in v0.1:**
- Per-alert verdicts with full evidence chain: correlated EVE records, enrichment results, rule clause explanation, attacker/victim role assignment
- GeoIP and ASN enrichment (offline, embedded), domain registration age via RDAP, VirusTotal reputation
- Internal hostname resolution via reverse DNS (PTR records for `HOME_NET` addresses)
- Disposition capture: accept the verdict or override it with a free-text reason

**Coming in v1:**
- Multi-user authentication and Active Directory identity integration
- Dashboard with team metrics and shift handoff notes
- Environment knowledge: admin-curated facts that improve verdict context ("10.5.5.5 is the vulnerability scanner")
- Install wizard

Feedback from early users shapes what gets built first. Use the feedback button in the top-right of the UI, or [open an issue](https://github.com/verdixsec/verdix/issues).

---

## Uninstalling

Verdix never modifies your Suricata configuration, SIEM, or network. Removing it is clean:

```bash
# Stop containers — stored verdicts and dispositions are preserved on the Docker volume
docker compose down

# Stop containers and delete all stored data
docker compose down -v
```

Nothing else to clean up.

---

## License

Source code: [AGPL-3.0](LICENSE). The source is fully auditable: read the code, build it yourself, verify every network call and data path.

The Docker images are distributed under the Verdix Community License, presented at first run. It permits free internal use at a single sensor without AGPL copyleft obligations.

---

## Trademark notices

Suricata is a registered trademark of the Open Information Security Foundation (OISF). Verdix is an independent open-source project and is not affiliated with, endorsed by, or sponsored by OISF.
