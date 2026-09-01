# Verdix Quickstart

This walks a bare Ubuntu box to a queue of Verdix verdicts on real malware traffic. It assumes a clean host with no other Docker workloads and no existing Suricata deployment — it installs Suricata first, then Verdix alongside it on the same host.

The traffic is a public FormBook infection capture from malware-traffic-analysis.net, replayed offline through Suricata. Nothing here configures live capture, and nothing touches a production network.

Allow about an hour, most of it unattended analysis, not the download: roughly 10-15 minutes to get Verdix running and traffic replayed, then 40 minutes to a couple hours while the model works through the queue, depending on your hardware.

---

## What you need

| | |
|---|---|
| **OS** | Ubuntu 22.04 LTS or newer, x86-64 only |
| **Hardware** | 4 physical cores (8 vCPU) · 16 GB RAM |
| **Disk** | 30 GB free **at Docker's storage location**, which is often not the same filesystem as your home directory. Step 3 checks this. |
| **Network** | Outbound HTTPS for the image pull and for RDAP lookups during analysis |

These are walkthrough figures. For production Verdix recommends 32 GB of RAM and 8 physical cores (16 vCPU); the disk floor is the same 30 GB either way. The health screen measures memory and cores against the production figures, so on a box this size it reports low memory and — since the check counts physical cores, not vCPU — a CPU warning. Both are expected here and neither stops the run. A production sensor triaging a live feed all day is what the larger memory and core figures cover; a throwaway box replaying one trimmed capture does not need them.

Fewer cores means slower verdicts, not worse ones — see "Why your run may differ" below for the caveats that apply regardless of hardware.

---

## 1. Install Suricata

The Ubuntu archive lags several major versions behind. Use the OISF stable PPA:

```bash
sudo add-apt-repository -y ppa:oisf/suricata-stable
sudo apt update
sudo apt install -y suricata
```

Pull the Emerging Threats Open ruleset:

```bash
sudo suricata-update
```

Confirm the version:

```bash
suricata --build-info | head -n 1
```

You should see Suricata 8.0.3 or above.

Leave `/etc/suricata/suricata.yaml` alone. The stock `HOME_NET` covers RFC1918, which is what this capture uses, and Verdix reads that file to work out which side of each alert is internal.

The package creates `/var/log/suricata/` and an empty `eve.json` inside it. That file is what Verdix tails, and it needs to exist before Verdix starts, so do not delete it.

The `suricata` service may fail to start on a host with no configured capture interface. That is expected. Offline replay runs Suricata directly, not through the service.

---

## 2. Install Docker

Skip this if `docker compose version` already prints a version.

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER && newgrp docker
docker run hello-world
```

You should see `Hello from Docker!`

---

## 3. Check disk space where Docker stores images

Skip this and the first-run pull can fail partway through with **no space left on device**, leaving a half-written image store to clean up before you can retry. Verdix consumes about 22 GB on disk — the app and LLM images plus the 11 GB model — all landing wherever Docker keeps its data, not in your home directory. `df -h /` is not the check.

```bash
docker info --format '{{.DockerRootDir}}'
df -h "$(docker info --format '{{.DockerRootDir}}')"
```

30 GB available on that filesystem is the floor for finishing this walkthrough (~22 GB consumed), with headroom to spare.

Short on space? Move Docker's data directory to a larger disk before you pull anything. The Deployment Guide covers this under "Moving Docker storage to a larger disk"; the link is at the end of this page.

---

## 4. Configure Verdix

```bash
mkdir -p ~/verdix && cd ~/verdix

curl -fsSL https://raw.githubusercontent.com/verdixsec/verdix/main/docker-compose.yml -o docker-compose.yml
curl -fsSL https://raw.githubusercontent.com/verdixsec/verdix/main/example.env -o .env
```

The two path variables already point at `/var/log/suricata` and `/etc/suricata`, which is where the package put them. Open `.env` and set the one remaining value:

```bash
VX_ADMIN_PASSWORD=choose-a-password
```

Leave everything else at its default.

---

## 5. Start Verdix

```bash
docker compose up -d
```

The first run transfers about 15 GB and unpacks to ~22 GB on disk — roughly 90 seconds on a fast connection, longer on a slower one. Every start after this one is quick, because the model stays in the `verdix_models` volume.

Watch it come up:

```bash
docker compose logs -f app
```

Look for `eve_tailer_started` and `suricata_config_loaded`. Both appear within about 30 seconds of the containers starting.

---

## 6. Log in

Open `http://localhost:8080`, or `http://<this-host-ip>:8080` from another machine on the network. Accept the licence, then log in with the password you set in `.env`.

The queue is empty. That is the expected state: Suricata has produced no alerts yet.

---

## 7. Download the sample capture

Ubuntu Server does not ship `unzip`:

```bash
sudo apt install -y unzip
```

Download and extract:

```bash
mkdir -p ~/verdix-sample && cd ~/verdix-sample
curl -O https://www.malware-traffic-analysis.net/2023/06/30/2023-06-30-Formbook-infection-traffic.pcap.zip
unzip -P infected_20230630 2023-06-30-Formbook-infection-traffic.pcap.zip
```

Every capture on that site is protected the same way.

Verdix ships no sample data. You are downloading the original capture from its publisher, and nothing derived from it is redistributed in this repository.

---

## 8. Trim the capture

The capture runs about eight hours and produces 1261 alerts. Verdix admits 300 alerts per day by default, so most of those would be stored as deferred and never analyzed.

Ubuntu Server images vary on whether `tcpdump` is present:

```bash
sudo apt install -y tcpdump
```

Cut the first 600 packets:

```bash
tcpdump -r 2023-06-30-Formbook-infection-traffic.pcap -c 600 -w formbook-trim.pcap
```

600 is the smallest cut that still contains all five signature types the full capture produces.

---

## 9. Replay through Suricata

```bash
sudo suricata -r formbook-trim.pcap -l /var/log/suricata/ -k none
```

This appends to the same `eve.json` Verdix is already tailing, so alerts reach the queue as Suricata emits them. `-k none` disables checksum validation, which published captures frequently fail because the capturing host offloaded checksums to its NIC.

Alerts land within seconds. The first verdict takes noticeably longer than the rest, because the model loads into memory on the first call with nothing on screen to say so.

The alerts appear under the default "Last 24h" view even though the traffic is from 2023. Verdix filters on when it received an alert, not on the timestamp inside the packet.

---

## What you should see

23-24 alerts land as 16 queue rows: 13 true positives, 1 false positive, and 2 flagged for investigation. The two DNS rows are the most sensitive to your Suricata ruleset version, so their exact verdicts can move between false-positive and investigate — either is expected.

FormBook beacons to a dozen different C2 addresses, and each one keeps its own row. The row counts below are queue rows; the alert counts are the raw Suricata events behind them.

Reference run, recorded 2026-08-28 on the 0.32.15 + `think:false` build, Suricata 8.0.3 with the ET Open ruleset as of that date, and no VirusTotal key configured. This records what that run produced, not what every install will reproduce:

| Signature | Sev | Rows | Alerts | Verdict |
|---|---|---|---|---|
| `ET MALWARE FormBook CnC Checkin (GET)` | S1 | 12 | 13 | `TP` |
| `SURICATA HTTP Response excessive header repetition` | S3 | 1 | 1 | `TP` |
| `ET INFO Observed DNS Query to .work TLD` | S2 | 1 | 5 | `INVESTIGATE` |
| `ET INFO Observed DNS Query to .cfd TLD` | S3 | 1 | 3 | `FP` |
| `ET DNS Query to a *.top domain - Likely Hostile` | S2 | 1 | 1-2 | `INVESTIGATE` |

Three verdict classes, with no API keys configured anywhere. Those five signature types are why the cut in step 8 is 600 packets and not fewer. The DNS-row verdicts and the `.top` alert count vary run to run — the OISF PPA serves different Suricata point releases across Ubuntu versions and the ET Open ruleset changes over time, so a different ruleset can move the `.work` and `.cfd` rows between false-positive and investigate. This run used 8.0.3; step 1's "8.0.3 or above" is the floor you install to. Neither variance is a sign something's wrong.

Rows analyze a few at a time, so expect `queued` and `analyzing...` badges while the run works through the backlog. Nothing is wrong; the model handles one alert at a time.

Open any row and the evidence panel shows what the verdict was built from: the correlated flow, DNS, and HTTP records sharing that `flow_id`, the enrichment results, the role assignment, and a per-source ledger recording which sources contributed and which had nothing to return.

### Why your run may differ

Verdix runs the model at temperature 0, which favors consistent output but does not guarantee byte-identical verdicts run to run: Ollama's prompt prefix cache is a known source of divergence on its own, observed in testing on the same machine with identical input and RDAP results. Input can also differ between runs — GeoIP is embedded in the image and offline, but RDAP is a live query against the relevant TLD registry, and registries change their answers and sometimes time out.

When a source degrades, the ledger says so on the alert page, and a verdict built on a thinner ledger can differ from the table above. Treat that table as a dated snapshot of one run, not a guarantee.

---

## Next

You have a working single-host deployment reading a real `eve.json`. Point `VX_SURICATA_LOG_DIR` at a live sensor's log directory and the same install starts triaging production alerts.

For Suricata on a separate host over NFS or SMB, VirusTotal configuration, health checks, storage sizing, and troubleshooting, see the [Deployment Guide](docs/DEPLOYMENT.md).
