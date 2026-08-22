<div align="center">

# Verdix

**Open-source AI triage for Suricata alerts — running entirely on your hardware.**

<!-- Screenshot: queue view showing analyzed alerts with TP/FP/suspicious verdicts -->
<!-- Add: docs/images/queue.png -->

[![Status: Early Access](https://img.shields.io/badge/status-Early%20Access-orange)](https://github.com/verdixsec/verdix)
[![Version: v0.2.0](https://img.shields.io/badge/version-v0.2.0-blue)](https://github.com/verdixsec/verdix/releases/tag/v0.2.0)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)

</div>

---

A tuned Suricata deployment can still put hundreds of EVE alerts a day in front of a Tier 1 analyst who can't read Suricata rule syntax fast enough to triage them at speed. Volume isn't the hard part. Each alert is the same dozen manual steps: correlate the `flow_id`, read the signature, enrich the indicators, work out the real source and target.

Verdix does those steps and shows its work. It drops in next to your existing Suricata installation via Docker, reads your `eve.json` in real time, and produces a verdict for each alert with the full evidence chain attached.

Your Suricata keeps running exactly as it was, and your SIEM keeps getting the same alerts.

**The AI runs in Docker on your own hardware. No payload data leaves the host.**

---

## How it works

For each Suricata alert, Verdix:

1. Reads all related `eve.json` records from the same network flow: the flow record, DNS queries, HTTP requests, TLS handshakes, and file events correlated by `flow_id`
2. Enriches the indicators: country and ASN from an embedded database (no internet required), internal hostnames via reverse DNS for your `HOME_NET` addresses, domain registration age and registrar via RDAP, and reputation via VirusTotal if you provide a free API key
3. Reads your `suricata.yaml` to understand your `HOME_NET`, then assigns attacker and victim roles from the rule's explicit `target` declaration where the rule provides one, then rule metadata, then a mapping from the alert category combined with which side of the network each address sits on. When none of those gives a clear answer, Verdix marks the assignment ambiguous rather than guessing.
4. Passes everything to a local LLM (Gemma 4, running in the sibling Docker container) which explains what the rule detected, what is actually happening in this specific alert, and recommends a verdict: *likely false positive*, *suspicious — investigate*, or *likely true positive*
5. Shows you the verdict with every piece of evidence it used: correlated records, enrichment results, rule explanation, role assignment, and a per-source ledger showing exactly what contributed and what was unavailable

You accept the verdict or override it. Verdix never takes action on an alert autonomously.

---

## Requirements

| | |
|---|---|
| **Hardware** | 32 GB RAM · 16 CPU cores · 60 GB free disk space |
| **GPU** | Not required. If present, Ollama uses it automatically, reducing verdict time from about three minutes to ~30 sec (projected, not yet measured) |
| **Software** | Docker 24+ with the `docker compose` plugin · Suricata running and producing `eve.json` |
| **OS** | Ubuntu 22.04 LTS+, Debian 11+, RHEL 8+, Rocky Linux 8+, AlmaLinux 8+, or Fedora (current release, or the previous release), or equivalent |
| **Network** | Outbound HTTPS required for RDAP domain lookups · optional but recommended for VirusTotal · GeoIP works fully offline |

**Capacity.** Verdix analyzes up to 300 alerts per day. Beyond that, alerts are stored and shown in the queue marked deferred, and do not receive a verdict. See the [Deployment Guide](docs/DEPLOYMENT.md#before-you-begin) for how the limit is counted and how to raise it.

Disk space splits across two locations: Docker's image store and the model volume. See the [Deployment Guide](docs/DEPLOYMENT.md#before-you-begin) for the breakdown and what to do if you relocate Docker storage.

---

## Try it in an hour

No Suricata deployment yet? [QUICKSTART.md](QUICKSTART.md) installs Suricata and Verdix on one throwaway Ubuntu box and walks you to a populated queue of verdicts on a public malware capture. Plan for 8 CPU cores, 30 GB RAM, and a ~22 GB image pull.

---

## Install

Verdix runs as two Docker containers alongside your existing Suricata. Install is `docker compose up` once `.env` points at your `eve.json` and `suricata.yaml` directories. First run pulls ~22 GB and takes 10–20 minutes.

See the [Deployment Guide](docs/DEPLOYMENT.md) for same-host, NFS, and SMB topologies, Docker installation, and storage sizing. Full configuration reference: [`example.env`](example.env).

---

## Your first verdict

The queue shows alerts as they arrive from `eve.json`. Each alert is analyzed automatically: about three minutes per alert on CPU, or ~30 seconds (projected, not yet measured) if a GPU is present.

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
| Verdict accuracy (development set) | **78.47%** |
| Verdict accuracy (held-out set) | **81.13%** |
| False-negative rate | **0.0%** |
| Structured output reliability | **100%** |

The corpus holds 327 alerts, each labeled with a ground-truth verdict by an experienced analyst. We split it into a 274-alert development set and a 53-alert held-out test set along source and family boundaries, so no alert family appears in both; the held-out alerts come from sources the prompt was never tuned against. Accuracy was 78.47% on the development set and 81.13% on the held-out set. Every verdict ran at temperature 0 (greedy decoding), so the score is deterministic and reproduces run to run.

Each entry carries a fixed set of threat-intelligence labels curated when the corpus was built. Most of these PCAPs are several years old and their indicators no longer return results from live VirusTotal, so the labels come from the IOCs the PCAP authors published alongside the captures. The harness renders them into the same prompt template the product uses. It makes no live VirusTotal, RDAP, or GeoIP calls, so these figures measure verdict quality given that context rather than the enrichment pipeline itself.

The corpus is built from malware PCAPs replayed through Emerging Threats Open rules, plus benign traffic from three sources: IoT-23 (a labeled academic honeypot-capture dataset), a capture of a personal host, and scripted traffic that trips Emerging Threats rules without being malicious. It covers the categories Suricata sensors actually fire on: infostealers, RATs, loaders, and C2 frameworks (Lumma, AsyncRAT, AgentTesla, Remcos, RedLine, Cobalt Strike, and others).

**0.0% false-negative rate.** Measured on the eval harness with static, curated threat-intel labels and no live enrichment calls: zero of 163 true-positive alerts in the development set and zero of 14 in the held-out set were predicted as false positives; a suspicious_investigate call on a true-positive alert scores as a miss, not a false negative. The target is ≤5%; zero is the strongest possible result. Missing a real threat is the worst outcome for a security tool, so this is the number we watch most closely.

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
- On-demand analysis of deferred alerts

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
