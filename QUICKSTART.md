# Verdix Quickstart

This walks a bare Ubuntu box to a queue of Verdix verdicts on real malware traffic. It assumes you have no Suricata deployment yet, so it installs Suricata first, then Verdix alongside it on the same host.

The traffic is a public FormBook infection capture from malware-traffic-analysis.net, replayed offline through Suricata. Nothing here configures live capture, and nothing touches a production network.

Allow about an hour. Most of that is the image pull.

---

## What you need

| | |
|---|---|
| **OS** | Ubuntu 22.04 LTS or newer |
| **Hardware** | 8 CPU cores · 30 GB RAM |
| **Disk** | 25 GB free **at Docker's storage location**, which is often not the same filesystem as your home directory. Step 3 checks this. |
| **Network** | Outbound HTTPS for the image pull and for RDAP lookups during analysis |

These are walkthrough figures, not the product's. Verdix's reference configuration is 32 GB of RAM, 16 cores, and 60 GB of disk, and the health screen measures against that: on a box this size it reports low memory and low disk. Both warnings are expected here and neither stops the run. A production sensor writes `eve.json` continuously and gets upgraded to new images, which is what the larger figures cover; a throwaway box replaying one trimmed capture does not.

Fewer cores means slower verdicts, not worse ones. The model is deterministic at temperature 0, so an 8-core box reaches the same verdicts as a 16-core box and takes longer doing it.

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

You should see Suricata 8.0.6 or newer.

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

Verdix pulls about 22 GB and unpacks it, and the model volume holds an 11 GB file. All of that lands wherever Docker keeps its data, not in your home directory. `df -h /` is not the check.

```bash
docker info --format '{{.DockerRootDir}}'
df -h "$(docker info --format '{{.DockerRootDir}}')"
```

Installing Verdix consumes about 24 GB on that filesystem, so 25 GB available is the floor for finishing this walkthrough. Below roughly 40 GB the health screen reports low disk and keeps reporting it, because it wants 15 GB still free after the install. On a test box that warning is expected.

If `docker info` reports `containerd` as the storage driver, images land under `/var/lib/containerd` instead and volumes stay under the path above. Check both:

```bash
df -h /var/lib/docker /var/lib/containerd
```

Short on space? Move Docker's data directory to a larger disk before you pull anything. The Deployment Guide covers this under "Moving Docker storage to a larger disk"; the link is at the end of this page. Doing it after a failed pull means cleaning up a half-written image store first.

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

The first run pulls roughly 22 GB and dominates the wait. Every start after this one is quick, because the model stays in the `verdix_models` volume.

Watch it come up:

```bash
docker compose logs -f app
```

Look for `eve_tailer_started` and `suricata_config_loaded`. Both appear within about 30 seconds of the containers starting.

Your own shell cannot list `/var/log/suricata/` without `sudo`, because the package restricts that directory to the `suricata` group. Verdix reads it anyway: the container starts as root, joins the group that owns the files, then drops to its unprivileged user. The entrypoint records which group it joined in the startup log.

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

The archive password is `infected_20230630`, passed above with `-P`. Every capture on that site is protected the same way.

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

24 alerts land as 16 queue rows: 13 true positives, 2 false positives, and 1 flagged for investigation.

Verdix groups by signature, source, and destination inside a one-hour window, so grouping only collapses repeat hits on the *same* destination. FormBook beacons to a dozen different C2 addresses, and each one keeps its own row. The row counts below are queue rows; the alert counts are the raw Suricata events behind them.

Reference run, recorded 2026-08-22 on Verdix v0.2.0 and Suricata 8.0.6, with no VirusTotal key configured:

| Signature | Sev | Rows | Alerts | Verdict |
|---|---|---|---|---|
| `ET MALWARE FormBook CnC Checkin (GET)` | S1 | 12 | 13 | `TP` 95% |
| `SURICATA HTTP Response excessive header repetition` | S3 | 1 | 1 | `TP` 95% |
| `ET INFO Observed DNS Query to .work TLD` | S2 | 1 | 5 | `FP` 40% |
| `ET INFO Observed DNS Query to .cfd TLD` | S3 | 1 | 3 | `FP` 40% |
| `ET DNS Query to a *.top domain - Likely Hostile` | S2 | 1 | 2 | `INVESTIGATE` 65% |

Three verdict classes spanning 40% to 95% confidence, with no API keys configured anywhere. Those five signature types are why the cut in step 8 is 600 packets and not fewer.

Rows analyze a few at a time, so expect `queued` and `analyzing...` badges while the run works through the backlog. Nothing is wrong; the model handles one alert at a time.

Open any row and the evidence panel shows what the verdict was built from: the correlated flow, DNS, and HTTP records sharing that `flow_id`, the enrichment results, the role assignment, and a per-source ledger recording which sources contributed and which had nothing to return.

### Why your run may differ

Verdix runs the model at temperature 0, so identical input produces an identical verdict every time. The input here is not fully identical between runs. GeoIP is embedded in the image and offline, but RDAP is a live query against the relevant TLD registry, and registries change their answers and sometimes time out.

When a source degrades, the ledger says so on the alert page, and a verdict built on a thinner ledger can differ from the table above. Treat that table as a dated snapshot of one run, not a guarantee.

---

## Next

You have a working single-host deployment reading a real `eve.json`. Point `VX_SURICATA_LOG_DIR` at a live sensor's log directory and the same install starts triaging production alerts.

For Suricata on a separate host over NFS or SMB, VirusTotal configuration, health checks, storage sizing, and troubleshooting, see the [Deployment Guide](docs/DEPLOYMENT.md).
