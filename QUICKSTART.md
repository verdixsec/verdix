# Verdix Quickstart

This walks a bare Ubuntu box to a queue of Verdix verdicts on real malware traffic, with no production Suricata sensor and no live network. You install Suricata and Verdix on a clean host, replay a public malware capture through them, and watch Verdix work the alerts Suricata produces.

Budget about an hour. Installing Suricata and Verdix and replaying the capture takes 15 to 30 minutes. Verdix then works through the queue in another 30 minutes to an hour, depending on your hardware. The capture is a public FormBook infection from malware-traffic-analysis.net, replayed offline. Nothing here touches a production network.

---

## What you need

| | |
|---|---|
| **OS** | Ubuntu 22.04 LTS or newer, x86-64 only |
| **Hardware** | 4 physical cores (8 vCPU) · 16 GB RAM |
| **Disk** | 30 GB free |
| **Network** | Outbound HTTPS for the image pull and for RDAP lookups during analysis |

On a box this size the health screen flags low memory and a CPU warning. Both are expected for this walkthrough and neither stops the run.

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

The package creates `/var/log/suricata/` and an empty `eve.json` inside it. Verdix tails that file, and it needs to exist before Verdix starts, so do not delete it.

---

## 2. Install Docker

Check whether Docker is already present:

```bash
docker compose version
```

If that prints a version, skip to Step 3. Otherwise install it:

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER && newgrp docker
docker run hello-world
```

You should see `Hello from Docker!`

---

## 3. Check disk space where Docker stores images

Verdix needs about 22 GB on disk: the app and LLM images plus the model. These land where Docker keeps its data, which is often a different filesystem from your home directory. Check that location, not `/`:

```bash
docker info --format '{{.DockerRootDir}}'
df -h "$(docker info --format '{{.DockerRootDir}}')"
```

Make sure that filesystem has at least 30 GB free before you pull anything.

Short on space? Move Docker's data directory to a larger disk first. The Deployment Guide covers this under "Moving Docker storage to a larger disk"; the link is at the end of this page.

---

## 4. Configure Verdix

```bash
mkdir -p ~/verdix && cd ~/verdix

curl -fsSL https://raw.githubusercontent.com/verdixsec/verdix/main/docker-compose.yml -o docker-compose.yml
curl -fsSL https://raw.githubusercontent.com/verdixsec/verdix/main/example.env -o .env
```

The defaults work for this walkthrough. The two path variables already point at `/var/log/suricata` and `/etc/suricata`, where the package put them. Leave `.env` as it is. You log in with the default password in Step 6.

---

## 5. Start Verdix

```bash
docker compose up -d
```

The first run transfers about 15 GB and unpacks to ~22 GB on disk. Depending on your connection this can take a few minutes. Every later start is quick; the model stays in the `verdix_models` volume.

Watch it come up:

```bash
docker compose logs -f app
```

Look for `eve_tailer_started` and `suricata_config_loaded`. Both appear within about 30 seconds of the containers starting.

---

## 6. Log in

Open `http://localhost:8080`, or `http://<this-host-ip>:8080` from another machine on the network. Accept the licence, then log in with the default password `changeme`.

The queue is empty. That is the expected state. Suricata has produced no alerts yet.

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

Verdix ships no sample data. You download the original capture from its publisher, and this repository redistributes nothing derived from it.

---

## 8. Trim the capture

The capture runs about eight hours and produces 1261 alerts. Verdix admits 300 alerts per day by default, so it would store most of those as deferred and never analyze them.

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

Alerts start appearing after Verdix's next poll of `eve.json`, usually within a minute. The first verdict takes longer than the rest. The model loads into memory on the first call and then stays resident, so later verdicts are faster.

The alerts appear under the default "Last 24h" view even though the traffic is from 2023. Verdix filters on when it received an alert, not on the timestamp inside the packet.

---

## What you should see

23-24 alerts land as 16 queue rows: 13 true positives, 1 false positive, and 2 flagged for investigation.

FormBook beacons to a dozen different C2 addresses, and each one keeps its own row. The row counts below are queue rows. The alert counts are the raw Suricata events behind them.

Reference run, recorded 2026-08-28 with Suricata 8.0.3 and the ET Open ruleset current on that date, no VirusTotal key configured. This records one run, not what every install reproduces:

| Signature | Sev | Rows | Alerts | Verdict |
|---|---|---|---|---|
| `ET MALWARE FormBook CnC Checkin (GET)` | S1 | 12 | 13 | `TP` |
| `SURICATA HTTP Response excessive header repetition` | S3 | 1 | 1 | `TP` |
| `ET INFO Observed DNS Query to .work TLD` | S2 | 1 | 5 | `INVESTIGATE` |
| `ET INFO Observed DNS Query to .cfd TLD` | S3 | 1 | 3 | `FP` |
| `ET DNS Query to a *.top domain - Likely Hostile` | S2 | 1 | 1-2 | `INVESTIGATE` |

Three verdict classes, all with no VirusTotal API key configured. Those five signature types are why the cut in step 8 is 600 packets and not fewer.

The DNS rows are the ruleset-sensitive part of this table. You install Suricata and its ET Open ruleset yourself, so a newer ruleset can move the `.work` and `.cfd` rows between false-positive and investigate. That variance is expected, not a sign anything is wrong.

Rows analyze a few at a time, so expect `queued` and `analyzing...` badges while the run works through the backlog. The model handles one alert at a time.

Open any row and the evidence panel shows what the verdict was built from: the correlated flow, DNS, and HTTP records sharing that `flow_id`, the enrichment results, the role assignment, and a per-source ledger of which sources contributed and which returned nothing.

### Why your run may differ

Verdix runs the model at temperature 0, so verdicts stay consistent but not always byte-identical between runs. RDAP enrichment is a live lookup against TLD registries. Those registries change their answers and sometimes time out, so when the inputs shift the verdict can shift with them.

---

## Next

You have a working single-host deployment reading a real `eve.json`. Point `VX_SURICATA_LOG_DIR` at a live sensor's log directory and the same install starts triaging production alerts. Set `VX_ADMIN_PASSWORD` in `.env` to something other than the default before you do.

For Suricata on a separate host over NFS or SMB, VirusTotal configuration, health checks, storage sizing, and troubleshooting, see the [Deployment Guide](docs/DEPLOYMENT.md).
