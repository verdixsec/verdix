# Verdix — Deployment Guide

> **Last updated:** 2026-05-21

Verdix needs direct access to Suricata's `eve.json`. The topology you need is determined by one question: **where is Suricata running relative to this host?** Same machine, separate Linux host, or Windows host/NAS. Pick the matching section below.

---

## Before you begin

**You need:**

- A supported Linux distribution: Ubuntu 22.04 LTS+, Debian 11+, RHEL 8+, Rocky Linux 8+, AlmaLinux 8+, or equivalent
- Docker 24+ with Docker Compose v2 (`docker compose`, not `docker-compose`); see [Install Docker](#install-docker) if not already installed
- Suricata already running and producing `eve.json`, either on this host or a networked sensor
- **32 GB RAM minimum**: the LLM runs in-process and needs memory headroom
- **40 GB free disk space** in Docker's storage area: the LLM image alone is ~13 GB
- **16 cores recommended, 8 minimum**: no GPU required; if one is present, Ollama uses it automatically and verdict latency drops from ~2 min to ~30 sec

**You don't need:**

- A GPU
- Any changes to your Suricata config, SIEM, or production network
- An internet connection for core functionality (VirusTotal is optional)

> **Disk space:** if Docker's data directory is on a small root partition, move it before pulling images. See [Moving Docker storage](#moving-docker-storage).

---

## Which topology is right for you?

| Your setup | Go to |
|---|---|
| Suricata and Verdix on the **same host** | [Topology 1](#topology-1-same-host) |
| Suricata on a **separate Linux host** | [Topology 2 — NFS](#topology-2-separated-nfs) |
| Suricata on a **Windows host or NAS** | [Topology 3 — SMB/CIFS](#topology-3-separated-smb-cifs) |

---

## Install Docker

Skip this section if `docker compose version` already shows a version number.

**Ubuntu 22.04 LTS / Debian 12 or newer:**
```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER && newgrp docker
docker run hello-world
```

You should see `Hello from Docker!`

**RHEL 8+ / Rocky Linux / AlmaLinux / Oracle Linux:**
```bash
sudo dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER && newgrp docker
docker run hello-world
```

---

## Topology 1: Same-host

Suricata and Verdix run on the same machine.

```
┌──────────────────────────────────────────────────┐
│  Host (32 GB RAM, 16 cores)                      │
│                                                  │
│  Suricata ──► /var/log/suricata/eve.json         │
│                        │                         │
│        ┌───────────────▼─────────────────────┐   │
│        │  docker compose up                  │   │
│        │  Verdix  (port 8080)       │   │
│        │  Ollama           (internal only)   │   │
│        └─────────────────────────────────────┘   │
└──────────────────────────────────────────────────┘
```

### Step 1 — Download and configure

```bash
mkdir -p ~/verdix && cd ~/verdix

curl -fsSL https://raw.githubusercontent.com/verdixsec/verdix/main/docker-compose.yml -o docker-compose.yml
curl -fsSL https://raw.githubusercontent.com/verdixsec/verdix/main/example.env -o .env
```

Open `.env` and set these values:

```bash
# [REQUIRED] Password for the web UI
VX_ADMIN_PASSWORD=choose-a-strong-password

# [REQUIRED] Directory on this host containing eve.json
VX_SURICATA_LOG_DIR=/var/log/suricata

# [REQUIRED] Directory on this host containing suricata.yaml
VX_SURICATA_CONFIG_DIR=/etc/suricata

# Optional — free key at virustotal.com/gui/my-apikey
# Strongly recommended: VT enrichment meaningfully improves verdict accuracy
VX_VIRUSTOTAL_API_KEY=
```

Common path variants by Suricata installation method:

| Installation | `VX_SURICATA_LOG_DIR` | `VX_SURICATA_CONFIG_DIR` |
|---|---|---|
| Package manager (apt / dnf / yum) | `/var/log/suricata` | `/etc/suricata` |
| SELKS | `/var/log/suricata` | `/etc/suricata` |
| Security Onion | `/nsm/suricata/logs` | `/etc/suricata` |
| pfSense + Suricata | `/var/log/suricata` | `/usr/local/etc/suricata` |
| Custom install | wherever `eve-log.filename` points | wherever `suricata.yaml` lives |

> Set these to directories, not filenames. Docker mounts them read-only into the container.

### Step 2 — Start

```bash
docker compose up -d
```

The first run pulls the app image (~2 GB) and the LLM image with the Gemma model baked in (~13 GB). This takes 10–20 minutes depending on your connection speed. Every subsequent start is instant.

Watch the startup:
```bash
docker compose logs -f app
```

> **Checkpoint:** you should see `eve_tailer_started` and `suricata_config_loaded` within 30 seconds of the containers coming up.

### Step 3 — Open the UI

Open `http://localhost:8080` in a browser on this host, or `http://HOST_IP:8080` from any machine on the same network (replace `HOST_IP` with this host's IP address).

> **Firewall note:** if this host has a firewall, allow inbound TCP 8080 from your analyst workstations:
> ```bash
> # Ubuntu/Debian (ufw)
> sudo ufw allow from YOUR_WORKSTATION_IP to any port 8080
> # RHEL/Rocky/Alma (firewalld)
> sudo firewall-cmd --permanent --add-port=8080/tcp && sudo firewall-cmd --reload
> ```

Accept the EULA, then log in with the admin password you set in `.env`.

**Trigger a test alert** to confirm the pipeline is working end-to-end:

```bash
curl http://testmynids.org/uid/index.html
```

This fires `ET ATTACK_RESPONSE Id Check Returned User Id` immediately. The alert appears in the queue within 30 seconds; the LLM verdict follows in ~2 minutes on a 16-core host.

---

## Topology 2: Separated — NFS

Suricata runs on a dedicated **sensor**. Verdix runs on a separate **analysis host**. The sensor's log and config directories are exported read-only via NFS and mounted on the analysis host.

```
┌──────────────────────┐    NFS (ro)    ┌──────────────────────────────────────────────┐
│  Sensor              │ ─────────────► │  Analysis host (32 GB RAM, 16 cores)         │
│  (Suricata)          │                │                                              │
│  /var/log/suricata/  │                │  /mnt/suricata_logs/                         │
│  /etc/suricata/      │                │  /mnt/suricata_config/                       │
└──────────────────────┘                │                                              │
                                        │  docker compose up                           │
                                        │  Verdix  (port 8080)                │
                                        │  Ollama           (internal only)            │
                                        └──────────────────────────────────────────────┘
```

**What this asks of the sensor:** two read-only export lines in `/etc/exports`. The exports are strictly read-only; Verdix cannot write to the sensor. They can be revoked in seconds.

> **About `docker-compose.override.yml`:** Docker Compose automatically merges a file named `docker-compose.override.yml` with `docker-compose.yml` on every `docker compose` command; no extra flags needed. In this topology you'll create one to store the NFS mount paths and a file-permission setting specific to this machine. It is gitignored, so updates to Verdix never overwrite it.

---

### Step A — On the sensor: export via NFS

#### A1 — Install and start the NFS server

**Ubuntu / Debian:**
```bash
sudo apt-get update && sudo apt-get install -y nfs-kernel-server
```

**RHEL 8+ / Rocky / AlmaLinux / Oracle Linux:**
```bash
sudo dnf install -y nfs-utils
sudo systemctl enable --now nfs-server rpcbind
```

**openSUSE / SLES:**
```bash
sudo zypper install -y nfs-kernel-server
sudo systemctl enable --now nfsserver
```

> **Checkpoint:** `sudo systemctl is-active nfs-server` prints `active`.

#### A2 — Add the export entries

Replace `ANALYSIS_HOST_IP` with the IP address of your analysis host:

```bash
echo '/var/log/suricata  ANALYSIS_HOST_IP(ro,sync,no_subtree_check)' | sudo tee -a /etc/exports
echo '/etc/suricata      ANALYSIS_HOST_IP(ro,sync,no_subtree_check)' | sudo tee -a /etc/exports
sudo exportfs -ra
```

> **Checkpoint:** `sudo exportfs -v` lists both paths with `(ro,...)`.

If your Suricata logs or config live in non-standard paths, adjust the left side of each line. Refer to the path table in [Topology 1](#step-1--download-and-configure) for common variants.

#### A3 — Open the firewall (if applicable)

**Ubuntu / Debian (ufw):**
```bash
sudo ufw allow from ANALYSIS_HOST_IP to any port 2049
sudo ufw allow from ANALYSIS_HOST_IP to any port 111
sudo ufw reload
```

**RHEL / Oracle Linux (firewalld):**
```bash
sudo firewall-cmd --permanent --add-service=nfs --source=ANALYSIS_HOST_IP
sudo firewall-cmd --permanent --add-service=rpc-bind --source=ANALYSIS_HOST_IP
sudo firewall-cmd --reload
```

**No firewall or internal-only network:** skip this step.

> **Checkpoint:** from the analysis host: `nc -zv SENSOR_IP 2049` prints `succeeded`.

---

### Step B — On the analysis host: mount, configure, and start

#### B1 — Install the NFS client

**Ubuntu / Debian:**
```bash
sudo apt-get install -y nfs-common
```

**RHEL / Rocky / AlmaLinux / Oracle Linux:**
```bash
sudo dnf install -y nfs-utils && sudo systemctl enable --now rpcbind
```

#### B2 — Mount and verify

Replace `SENSOR_IP` with the sensor's IP address:

```bash
sudo mkdir -p /mnt/suricata_logs /mnt/suricata_config

sudo mount -t nfs SENSOR_IP:/var/log/suricata /mnt/suricata_logs
sudo mount -t nfs SENSOR_IP:/etc/suricata     /mnt/suricata_config

ls /mnt/suricata_logs/eve.json         # should succeed
ls /mnt/suricata_config/suricata.yaml  # should succeed
```

> **Checkpoint:** both `ls` commands return the file without errors.
> - "Permission denied" → check Step A3 (firewall)
> - "No such file or directory" → check the paths in Step A2

#### B3 — Make mounts survive reboots

```bash
echo 'SENSOR_IP:/var/log/suricata  /mnt/suricata_logs    nfs  ro,soft,timeo=30,_netdev  0  0' | sudo tee -a /etc/fstab
echo 'SENSOR_IP:/etc/suricata      /mnt/suricata_config  nfs  ro,soft,timeo=30,_netdev  0  0' | sudo tee -a /etc/fstab

# Test without rebooting
sudo umount /mnt/suricata_logs /mnt/suricata_config
sudo mount /mnt/suricata_logs && sudo mount /mnt/suricata_config
ls /mnt/suricata_logs/eve.json && echo "OK"
```

> The `_netdev` option tells the OS to wait for the network before mounting at boot. Without it, a reboot while the sensor is unreachable can hang the boot sequence.

#### B4 — Download and configure

```bash
mkdir -p ~/verdix && cd ~/verdix

curl -fsSL https://raw.githubusercontent.com/verdixsec/verdix/main/docker-compose.yml -o docker-compose.yml
curl -fsSL https://raw.githubusercontent.com/verdixsec/verdix/main/example.env -o .env
```

In `.env`, point to the NFS mount paths:

```bash
VX_ADMIN_PASSWORD=choose-a-strong-password
VX_SURICATA_LOG_DIR=/mnt/suricata_logs
VX_SURICATA_CONFIG_DIR=/mnt/suricata_config
VX_VIRUSTOTAL_API_KEY=    # optional but recommended
```

#### B5 — Fix container file permissions

Verdix runs inside the container as a non-root user. Suricata's `eve.json` is group-owned by Suricata's process group. The container needs to be added to that group. The group ID varies by distro and Suricata install method, so detect it automatically:

```bash
SURICATA_GID=$(stat -c "%g" /mnt/suricata_logs/eve.json)
echo "Detected GID: $SURICATA_GID"

cat > docker-compose.override.yml << EOF
# Machine-specific overrides — not committed to git.
# Docker Compose merges this automatically with docker-compose.yml.
services:
  app:
    group_add:
      - "${SURICATA_GID}"
    volumes:
      - /mnt/suricata_logs:/host/suricata/logs:ro
      - /mnt/suricata_config:/host/suricata/config:ro
EOF
```

#### B6 — Start

```bash
docker compose up -d
docker compose logs -f app
```

> **Checkpoint:** `eve_tailer_started` appears in the logs. Open `http://localhost:8080` on this host, or `http://ANALYSIS_HOST_IP:8080` from your analyst workstation.

> **Firewall note:** if this host has a firewall, allow inbound TCP 8080 from your analyst workstations:
> ```bash
> sudo ufw allow from YOUR_WORKSTATION_IP to any port 8080        # ufw
> sudo firewall-cmd --permanent --add-port=8080/tcp && sudo firewall-cmd --reload  # firewalld
> ```

**If eve.json is not being read:**
```bash
docker compose exec app tail -1 /host/suricata/logs/eve.json
```
If this returns "Permission denied", the group ID in Step B5 is wrong. Re-run `stat -c "%g" /mnt/suricata_logs/eve.json`, update `docker-compose.override.yml`, then `docker compose down && docker compose up -d`.

---

## Topology 3: Separated — SMB/CIFS

Use this when the sensor is a Windows host or a NAS exporting via Samba.

```
┌────────────────────────────┐  SMB/CIFS (ro)   ┌──────────────────────────────────────────────┐
│  Sensor                    │ ───────────────► │  Analysis host (32 GB RAM, 16 cores)         │
│  (Windows / NAS)           │                  │                                              │
│  \\sensor\suricata-logs    │                  │  /mnt/suricata_logs/                         │
│  \\sensor\suricata-config  │                  │  /mnt/suricata_config/                       │
└────────────────────────────┘                  │                                              │
                                                │  docker compose up                           │
                                                │  Verdix  (port 8080)                │
                                                │  Ollama           (internal only)            │
                                                └──────────────────────────────────────────────┘
```

Replace `SENSOR_IP` with the sensor's IP address or hostname.

```bash
sudo apt-get install -y cifs-utils    # Ubuntu/Debian
# sudo dnf install -y cifs-utils     # RHEL/Rocky/Alma

sudo mkdir -p /mnt/suricata_logs /mnt/suricata_config

sudo mount -t cifs //SENSOR_IP/suricata-logs   /mnt/suricata_logs   \
  -o ro,username=guest,password=,uid=$(id -u),gid=$(id -g)
sudo mount -t cifs //SENSOR_IP/suricata-config /mnt/suricata_config \
  -o ro,username=guest,password=,uid=$(id -u),gid=$(id -g)
```

Once the mounts are working, follow [Steps B4–B6](#b4--download-and-configure) from Topology 2, using `/mnt/suricata_logs` and `/mnt/suricata_config` as your paths.

> **Note:** Windows `suricata.yaml` files sometimes use backslash path separators in `include:` directives. The config reader normalises them automatically.

---

## Testing with sample traffic

To confirm the pipeline is working, run this on the sensor:

```bash
curl http://testmynids.org/uid/index.html
```

This fires `ET ATTACK_RESPONSE Id Check Returned User Id` and produces an alert in `eve.json` within seconds.

For richer testing with real malware signatures (VirusTotal hits, RDAP domain data, high-confidence TP verdicts), replay a labeled PCAP through Suricata on the sensor:

```bash
sudo suricata -r /path/to/sample.pcap -l /var/log/suricata/ -k none
```

**Replayed alerts appear immediately in the "Last 24h" queue view.** Verdix filters by when it received the alert, not the timestamp inside the PCAP. Historical PCAPs from weeks or months ago show up alongside live alerts without any special handling.

**Recommended source:** [malware-traffic-analysis.net](https://malware-traffic-analysis.net) provides labeled real-world PCAPs by malware family and date. These exercise the full enrichment pipeline (C2 traffic, exploit kit activity, infostealer patterns) and produce high-confidence verdicts.

---

## Troubleshooting

**Container exits immediately:**
```bash
docker compose logs app
# Look for: VX_ADMIN_PASSWORD not set, or eve.json path not found
```

**No verdicts after 10 minutes:**
```bash
# Is the tailer reading eve.json?
docker compose logs app | grep eve_tailer

# Is Suricata producing alert events?
tail -f /your/VX_SURICATA_LOG_DIR/eve.json | grep '"event_type":"alert"'
```

**Ollama model still loading (first run only):**
```bash
docker compose logs llm
# "pulling..." → still downloading; wait for "success" before expecting verdicts
```

**VirusTotal shows NOT_CONFIGURED:**
```bash
docker compose exec app printenv VX_VIRUSTOTAL_API_KEY
# Empty output means the key is missing from .env
```

**suricata.yaml not loading:**
```bash
docker compose exec app ls /host/suricata/config/suricata.yaml
# If missing, VX_SURICATA_CONFIG_DIR points to the wrong directory
```

**Cannot reach the UI from another machine:**
The host's firewall may be blocking port 8080. See the firewall note in your topology's final step.

**NFS mounts missing after reboot:**
Ensure `/etc/fstab` entries include `_netdev`. Check `dmesg | grep nfs` for mount errors.

---

## Uninstalling

Verdix is a passive observer. Removing it leaves your Suricata, SIEM, and network exactly as they were.

```bash
# Stop containers (data preserved on the named volume)
docker compose down

# Full removal — deletes all stored verdicts, dispositions, and enrichment cache
docker compose down -v
```

---

## Optional configuration

### Moving Docker storage to a larger disk

If your root partition has less than 40 GB free, move Docker's storage before pulling images:

```bash
# Stop Docker
sudo systemctl stop docker

# Format and mount a new disk (replace /dev/vdb and /opt with your device/path)
sudo parted /dev/vdb --script mklabel gpt mkpart primary ext4 0% 100%
sudo mkfs.ext4 /dev/vdb1
sudo mount /dev/vdb1 /opt
echo "UUID=$(sudo blkid -s UUID -o value /dev/vdb1)  /opt  ext4  defaults  0  2" | sudo tee -a /etc/fstab

# Point Docker at the new location
sudo mkdir -p /opt/docker
echo '{"data-root": "/opt/docker"}' | sudo tee /etc/docker/daemon.json
sudo systemctl start docker

# Verify
docker info | grep "Docker Root Dir"   # should show /opt/docker
```

### TLS-inspecting proxy

Add to `.env`:

```bash
HTTP_PROXY=http://proxy.corp.example.com:8080
HTTPS_PROXY=http://proxy.corp.example.com:8080
NO_PROXY=localhost,llm,127.0.0.1
SSL_CERT_FILE=/host/certs/ca-bundle.pem    # only if the proxy uses a corporate CA
```

Mount your CA bundle in `docker-compose.override.yml`:

```yaml
services:
  app:
    volumes:
      - /path/to/ca-bundle.pem:/host/certs/ca-bundle.pem:ro
```

### Reverse DNS (internal hostnames in verdicts)

Verdix performs reverse DNS lookups on internal IPs to resolve hostnames. Machine names appear in verdicts instead of bare IPs. This works automatically when your DNS server has PTR records for internal hosts.

To use a specific DNS server instead of the system resolver:
```bash
VX_DNS_SERVER=10.0.0.53    # your internal DNS server IP
```

To disable reverse DNS entirely:
```bash
VX_REVDNS_ENABLED=false
```

### MaxMind GeoLite2 (if you already have the databases)

Verdix ships with DB-IP Community Edition built into the image. GeoIP enrichment works out of the box with no configuration.

If your organization already uses MaxMind GeoLite2 (`.mmdb` files from another security tool), you can point Verdix at those files instead:

1. Place `GeoLite2-Country.mmdb` and `GeoLite2-ASN.mmdb` somewhere on the host (e.g. `/opt/geoip/`).
2. Add to `docker-compose.override.yml`:

```yaml
services:
  app:
    volumes:
      - /opt/geoip:/host/geoip:ro
    environment:
      VX_GEOIP_COUNTRY_DB_PATH: /host/geoip/GeoLite2-Country.mmdb
      VX_GEOIP_ASN_DB_PATH: /host/geoip/GeoLite2-ASN.mmdb
```
