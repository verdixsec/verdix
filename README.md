<div align="center">

# Verdix

**Open-source AI triage for Suricata alerts — running entirely on your hardware.**

<!-- Screenshot: queue view showing analyzed alerts with TP/FP/suspicious verdicts -->
<!-- Add: docs/images/queue.png -->

[![Status: Early Access](https://img.shields.io/badge/status-Early%20Access-orange)](https://github.com/verdixsec/verdix)
[![Version: v0.1.1](https://img.shields.io/badge/version-v0.1.1-blue)](https://github.com/verdixsec/verdix/releases/tag/v0.1.1)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)

</div>

---

Your Suricata generates hundreds of EVE alerts a day. Most are false positives, but deciding which ones matter requires reading the rule grammar, correlating the surrounding flow records, enriching the indicators, and making a judgment call on every alert, every shift. Verdix does that work alongside you.

It drops in next to your existing Suricata installation via Docker. It reads your `eve.json` in real time, analyzes each alert, and produces a verdict with the full evidence chain attached. Your Suricata keeps running exactly as it was. Your SIEM keeps getting the same alerts. Nothing changes in your existing workflow. You have a second opinion on every alert.

**The AI runs in Docker on your own hardware. No alert data, no IPs, nothing leaves your network.**

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
| **Hardware** | 32 GB RAM · 16 CPU cores (8 minimum) · 40 GB free disk space |
| **GPU** | Not required. If present, Ollama uses it automatically, reducing verdict time from ~2 min to ~30 sec |
| **Software** | Docker 24+ with the `docker compose` plugin · Suricata running and producing `eve.json` |
| **OS** | Any Linux distribution that supports Docker 24+ (Ubuntu, Debian, RHEL, Rocky Linux, AlmaLinux, Fedora, openSUSE, and others) |
| **Network** | Outbound HTTPS optional but strongly recommended for VirusTotal · GeoIP works fully offline |

**macOS:** Docker Desktop on Apple Silicon works for evaluation. 32 GB unified memory is recommended so the model fits without swapping.

**First run:** `docker compose up` downloads approximately 15 GB of Docker images: the application (~2 GB) and the LLM image with Gemma baked in (~13 GB). Allow 10–15 minutes depending on your connection speed. This happens once; images are cached locally after the first pull. On every start, allow 1–2 minutes after the containers come up for the model to load into memory before verdicts begin.

---

## Quick start

> **Suricata on a different machine?** Mount its log and config directories over NFS first, then follow these steps using your mount paths. See the [NFS Deployment Guide](docs/DEPLOYMENT.md#topology-2-separated-nfs).

### Step 1 — Download

```bash
mkdir -p ~/verdix && cd ~/verdix

curl -fsSL https://raw.githubusercontent.com/verdixsec/verdix/main/docker-compose.yml -o docker-compose.yml
curl -fsSL https://raw.githubusercontent.com/verdixsec/verdix/main/example.env -o .env
```

### Step 2 — Configure

Open `.env` in any text editor and set these three values:

```bash
VX_ADMIN_PASSWORD=your-strong-password   # password for the web UI
VX_SURICATA_LOG_DIR=/var/log/suricata    # directory containing eve.json
VX_SURICATA_CONFIG_DIR=/etc/suricata     # directory containing suricata.yaml
```

Common paths by Suricata installation method:

| Installation | `VX_SURICATA_LOG_DIR` | `VX_SURICATA_CONFIG_DIR` |
|---|---|---|
| Package manager (apt, dnf, yum) | `/var/log/suricata` | `/etc/suricata` |
| SELKS | `/var/log/suricata` | `/etc/suricata` |
| Security Onion | `/nsm/suricata/logs` | `/etc/suricata` |
| pfSense + Suricata | `/var/log/suricata` | `/usr/local/etc/suricata` |
| Custom / manual build | wherever `eve-log.filename` points in your `suricata.yaml` | wherever your `suricata.yaml` lives |

**Also recommended:** add a free VirusTotal API key. It improves verdict accuracy on borderline alerts where IP or domain reputation is the deciding signal.

```bash
VX_VIRUSTOTAL_API_KEY=your-vt-key   # free key at virustotal.com/gui/my-apikey
```

### Step 3 — Start

```bash
docker compose up -d
```

The first run pulls ~15 GB of Docker images. Allow 10–15 minutes. Watch progress with `docker compose logs -f`. Once the containers are up, allow 1–2 minutes for the model to load into memory. When you see `eve_tailer_started` in the app logs, Verdix is reading your `eve.json`.

### Step 4 — Open the UI

Navigate to `http://localhost:8080` in a browser on this host, or `http://HOST_IP:8080` from any machine on the same network (replace `HOST_IP` with this host's IP address). Accept the EULA, review the health check, and log in with the password you set.

---

## Your first verdict

The queue shows alerts as they arrive from `eve.json`. Each alert is analyzed automatically. Expect about 2 minutes per alert on 16-core CPU-only hardware, or ~30 seconds if a GPU is present.

**To generate test traffic right now:**

If Suricata is monitoring a live network interface, run this on the Suricata host:
```bash
curl http://testmynids.org/uid/index.html
```
This fires the `ET ATTACK_RESPONSE Id Check Returned User Id` rule and produces an alert within seconds.

For more realistic alerts (including malware signatures with real VirusTotal and RDAP enrichment), replay a sample PCAP through Suricata on the Suricata host:
```bash
sudo suricata -r /path/to/sample.pcap -l /var/log/suricata/ -k none
```
Replayed alerts appear in the standard queue view immediately (the queue filters by when the alert arrived, not when the traffic occurred). See [Testing with Sample Traffic](docs/DEPLOYMENT.md#testing-with-sample-traffic) for recommended PCAP sources.

<!-- Screenshot: per-alert investigation view showing verdict, enrichment ledger, and evidence chain -->
<!-- Add: docs/images/alert.png -->

---

## Configuration reference

| Variable | Required | Default | Description |
|---|---|---|---|
| `VX_ADMIN_PASSWORD` | yes | — | Password for the web UI |
| `VX_SURICATA_LOG_DIR` | yes | `/var/log/suricata` | Host directory containing `eve.json` |
| `VX_SURICATA_CONFIG_DIR` | yes | `/etc/suricata` | Host directory containing `suricata.yaml` |
| `VX_VIRUSTOTAL_API_KEY` | no | — | Free VirusTotal API key. Improves verdict accuracy on borderline alerts |
| `VX_DNS_SERVER` | no | OS resolver | Explicit DNS server for internal hostname resolution via PTR lookups |
| `VX_TRIAGE_DAILY_CAP` | no | `300` | Maximum alerts auto-analyzed per day on this hardware |
| `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` | no | — | Standard proxy variables; all outbound HTTP calls respect these |

Full reference with all options and defaults: [`example.env`](example.env)

---

## Accuracy

Before writing any product code, we built an independent evaluation harness and assembled a labeled corpus of real Suricata alerts. The numbers below are its output, not our estimates.

| Metric | Result |
|---|---|
| Verdict accuracy | **79.2%** |
| False-negative rate | **0.0%** |
| Structured output reliability | **100%** |

The corpus holds 327 alerts, each labeled with a ground-truth verdict by an experienced analyst. We split it into a 274-alert development set and a 53-alert held-out test set along source boundaries, so no alert family appears in both; the held-out alerts come from sources the prompt was never tuned against. Accuracy was 79.2% on the held-out set and the same on the development set. Every verdict ran at temperature 0 (greedy decoding), so the score is deterministic and reproduces run to run. VirusTotal reputation, RDAP domain registration, and GeoIP enrichment ran on every entry, matching the production pipeline.

The corpus is built from malware PCAPs replayed through Emerging Threats Open rules plus benign false-positive traffic from real enterprise networks. It covers the categories Suricata sensors actually fire on: infostealers, RATs, loaders, and C2 frameworks (Lumma, AsyncRAT, AgentTesla, Remcos, RedLine, Cobalt Strike, and others).

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

## Troubleshooting

**App container exits immediately**
Check that `VX_ADMIN_PASSWORD` is set in `.env`, then `docker compose up -d` again.

**Queue is empty after 10 minutes**
Confirm the path is correct and the file exists inside the container:
```bash
docker compose exec app ls -la /host/suricata/logs/eve.json
```

**No verdicts appearing after alerts arrive**
Check that the Ollama container is healthy and the model is loaded:
```bash
docker compose ps
docker compose logs llm | tail -20
```

**"Permission denied" reading eve.json (NFS deployments)**
The container user needs to be added to the file's group. See [Fix Container File Permissions](docs/DEPLOYMENT.md#b5--fix-container-file-permissions).

**VirusTotal shows NOT_CONFIGURED**
Confirm the key reached the container:
```bash
docker compose exec app printenv VX_VIRUSTOTAL_API_KEY
```
If empty, ensure `VX_VIRUSTOTAL_API_KEY` is set in `.env` (not just in the shell).

**Health check shows a disk space warning**
At least 40 GB free space is needed in Docker's storage directory. See [Moving Docker storage to a larger disk](docs/DEPLOYMENT.md#moving-docker-storage-to-a-larger-disk) if your root partition is limited.

More: [Deployment Guide — Troubleshooting](docs/DEPLOYMENT.md#troubleshooting)

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
