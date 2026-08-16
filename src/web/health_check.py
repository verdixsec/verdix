# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""System health introspection for the /api/health endpoint and Setup screen.

Checks are grouped into five categories matching the design:
  - core:        eve.json, admin password, Ollama
  - resources:   RAM, CPU, GPU (optional), disk
  - network:     proxy configuration
  - enrichment:  VirusTotal, GeoIP, RDAP (all optional)
  - ingestion:   live pipeline state (ADR-019). Deliberately not merged with
                 core's eve.json check — the two answers can disagree and
                 the disagreement is the diagnosis; see _check_ingestion()

run_health_check() is async and performs live I/O (Ollama ping, RDAP probe).
All failures are caught and reported as check items — never raises.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import psutil

if TYPE_CHECKING:
    from src.ingestion.status import IngestionStatus


@dataclass
class CheckItem:
    label: str
    status: str          # "ok" | "warn" | "error" | "info"
    detail: str
    required: bool = False


@dataclass
class HealthResult:
    core: list[CheckItem] = field(default_factory=list)
    resources: list[CheckItem] = field(default_factory=list)
    network: list[CheckItem] = field(default_factory=list)
    enrichment: list[CheckItem] = field(default_factory=list)
    ingestion: list[CheckItem] = field(default_factory=list)

    @property
    def all_required_ok(self) -> bool:
        all_checks = self.core + self.resources + self.network + self.enrichment
        return all(c.status == "ok" for c in all_checks if c.required)

    def to_dict(self) -> dict[str, Any]:
        def items(lst: list[CheckItem]) -> list[dict]:
            return [
                {"label": c.label, "status": c.status,
                 "detail": c.detail, "required": c.required}
                for c in lst
            ]
        return {
            "core": items(self.core),
            "resources": items(self.resources),
            "network": items(self.network),
            "enrichment": items(self.enrichment),
            "ingestion": items(self.ingestion),
            "all_required_ok": self.all_required_ok,
        }


async def run_health_check(ingestion_status: IngestionStatus | None = None) -> HealthResult:
    """Run every check group.

    ingestion_status is optional (ADR-019 Stage 2): the two call sites
    (api_routes.api_health, setup.get_health_check) both have `request` and
    can pass `request.app.state.ingestion_status`, but this module otherwise
    has no access to app state. A missing status degrades to an "unknown"
    check item rather than raising, matching how every other check here
    reports absence (e.g. VirusTotal/GeoIP "not configured") instead of
    failing the whole health check.
    """
    result = HealthResult()
    result.core = await _check_core()
    result.resources = _check_resources()
    result.network = _check_network()
    result.enrichment = await _check_enrichment()
    result.ingestion = _check_ingestion(ingestion_status)
    return result


# ---------------------------------------------------------------------------
# Core checks
# ---------------------------------------------------------------------------

async def _check_core() -> list[CheckItem]:
    items: list[CheckItem] = []

    # eve.json — os.path.isfile()/os.access() are local predicates: over an
    # NFS mount, they answer against the container's local uid/gid view,
    # which can disagree with the server-side uid mapping that actually
    # decides whether a read succeeds (root_squash remaps uid 0 or an
    # unrecognized uid, independent of local group membership). On-box
    # verification against real NFS hit exactly this: os.access() reported
    # the file readable while the server denied the read, so the operator
    # was told to fix a bind mount that was already correct. Attempt the
    # real operation instead and branch on the OSError it raises — the only
    # way to see a server-side decision rather than predict it.
    eve_path = os.environ.get("VX_EVE_LOG_PATH", "/host/suricata/logs/eve.json")
    try:
        with open(eve_path, "rb"):
            pass
    except FileNotFoundError:
        items.append(CheckItem(
            "Alert log (eve.json)", "error",
            f"Not found at {eve_path} — update the bind mount path in "
            "docker-compose.yml and restart",
            required=True,
        ))
    except PermissionError:
        items.append(CheckItem(
            "Alert log (eve.json)", "error",
            f"Found at {eve_path} but permission denied — {_UNREADABLE_HINT}",
            required=True,
        ))
    except OSError as exc:
        items.append(CheckItem(
            "Alert log (eve.json)", "error",
            f"Cannot read {eve_path}: {exc}",
            required=True,
        ))
    else:
        items.append(CheckItem("Alert log (eve.json)", "ok",
                               f"Found at {eve_path}", required=True))

    # Admin password
    if os.environ.get("VX_ADMIN_PASSWORD"):
        items.append(CheckItem("Admin password", "ok", "Configured", required=True))
    else:
        items.append(CheckItem(
            "Admin password", "error",
            "VX_ADMIN_PASSWORD is not set — set VX_ADMIN_PASSWORD in docker-compose.yml and restart",
            required=True,
        ))

    # Ollama
    ollama_item = await _check_ollama()
    ollama_item.required = True
    items.append(ollama_item)

    return items


async def _check_ollama() -> CheckItem:
    from urllib.parse import urlparse, urlunparse

    from src.infra.http.factory import create_http_client

    ollama_url = os.environ.get("VX_OLLAMA_URL", "http://llm:11434/api/chat")
    default_model = os.environ.get("VX_OLLAMA_MODEL", "gemma4:e4b-it-q8_0")
    # SC_OLLAMA_URL is the full chat endpoint (e.g. http://host:11434/api/chat).
    # Strip the path to get the base URL for the tags probe.
    parsed = urlparse(ollama_url)
    base_url = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
    tags_url = f"{base_url}/api/tags"

    try:
        async with create_http_client(10.0, "ollama") as client:
            resp = await client.get(tags_url)
        if resp.status_code != 200:
            return CheckItem(
                "AI Engine (Ollama)", "error",
                f"Ollama returned HTTP {resp.status_code} — is the llm container running?",
            )
        data = resp.json()
        models = [m.get("name", "") for m in data.get("models", [])]
        if any(default_model in m for m in models):
            return CheckItem(
                "AI Engine (Ollama)", "ok",
                f"Running · {default_model} loaded",
            )
        if models:
            return CheckItem(
                "AI Engine (Ollama)", "warn",
                f"Ollama running but model '{default_model}' not found. "
                f"Available: {', '.join(models[:3])}",
            )
        return CheckItem(
            "AI Engine (Ollama)", "warn",
            f"Ollama running but no models loaded — pull {default_model}",
        )
    except Exception as exc:  # noqa: BLE001
        return CheckItem(
            "AI Engine (Ollama)", "error",
            f"Cannot reach Ollama at {ollama_url}: {exc} — is the llm container running?",
        )


# ---------------------------------------------------------------------------
# Ingestion checks (ADR-019)
# ---------------------------------------------------------------------------

def _check_ingestion(status: IngestionStatus | None) -> list[CheckItem]:
    """Live pipeline state only — deliberately separate from Core
    Requirements' eve.json readability check, not merged with it.

    The two answers can disagree: on 2026-08-12, after the NFS group was
    restored but before the container was restarted, the file would have
    read as readable while the pipeline was still dead. "File readable,
    pipeline stopped" means a restart is needed; "file unreadable, pipeline
    retrying" means the mount itself needs fixing. Reporting one combined
    status would erase that distinction, so this item stays on its own,
    required=False — a transient mid-run red does not gate all_required_ok
    (ADR-019 blocks only at startup, a later stage's concern).
    """
    if status is None:
        return [CheckItem(
            "Ingestion pipeline", "info",
            "Status unavailable — could not determine pipeline state",
        )]
    if status.state == "red":
        reason = status.blocked_reason or status.last_error or "unknown error"
        since = status.state_changed_at.isoformat() if status.state_changed_at else "unknown"
        return [CheckItem(
            "Ingestion pipeline", "error",
            f"Red since {since} — {reason}",
        )]
    return [CheckItem(
        "Ingestion pipeline", "ok", "Green — reading eve.json normally",
    )]


# Same remediation universe entrypoint.sh's check_and_fix() already prints
# for both paths (entrypoint.sh:63-65) — reused verbatim rather than
# inventing new phrasing, since the operator may have just read this in
# `docker compose logs`.
_UNREADABLE_HINT = (
    "check the mount and the export's root_squash setting. If the path "
    "exists but is still unreadable, this is usually SELinux (check "
    "'ls -Z' on the host) or a POSIX ACL beyond the owning group (check "
    "'getfacl'). Grant the app user (uid 38317) explicit read access, "
    "then restart."
)


def check_blocked_paths() -> dict[str, Any]:
    """Re-probe the two paths that can block startup (ADR-019 Stage 3).

    Used only by the Re-check action on /setup/health once ingestion is
    already blocked. Never clears blocked_reason and never starts the
    pipeline — EvePipeline/TriageWorker are constructed once, in the
    lifespan startup, and a fixed GID needs entrypoint.sh's group-join,
    which only runs at container start. Whether this reports success or
    failure, a container restart is what actually recovers either way.
    """
    from src.infra.suricata_config.reader import read_config

    suricata_path = os.environ.get(
        "VX_SURICATA_CONFIG_PATH", "/host/suricata/config/suricata.yaml"
    )
    suricata_error: str | None = None
    try:
        read_config(suricata_path)
    except Exception as exc:  # noqa: BLE001
        suricata_error = f"{exc} — {_UNREADABLE_HINT}"

    # Same local-predicate-vs-server-side-decision gap as _check_core()'s
    # eve.json item above — attempt the real read rather than predicting it.
    eve_path = os.environ.get("VX_EVE_LOG_PATH", "/host/suricata/logs/eve.json")
    eve_ok = True
    eve_error: str | None = None
    try:
        with open(eve_path, "rb"):
            pass
    except FileNotFoundError:
        eve_ok = False
        eve_error = f"{eve_path} does not exist — {_UNREADABLE_HINT}"
    except PermissionError:
        eve_ok = False
        eve_error = f"{eve_path} exists but permission denied — {_UNREADABLE_HINT}"
    except OSError as exc:
        eve_ok = False
        eve_error = f"Cannot read {eve_path}: {exc}"

    return {
        "suricata_yaml": {
            "path": suricata_path, "ok": suricata_error is None, "error": suricata_error,
        },
        "eve_json": {"path": eve_path, "ok": eve_ok, "error": eve_error},
        "all_ok": suricata_error is None and eve_ok,
    }


# ---------------------------------------------------------------------------
# Resource checks
# ---------------------------------------------------------------------------

_RAM_MINIMUM_GB = 16
_RAM_RECOMMENDED_GB = 32
_RAM_OK_GB = 30  # tolerance below _RAM_RECOMMENDED_GB — see comment below

# Scoped to what this check can actually see: VX_DATA_PATH's filesystem,
# i.e. wherever the verdix_data volume lands (below). It cannot observe
# Docker's image/layer store (~11 GB measured — ollama base + lean llm
# layer + app image) — the app container has no docker.sock, no docker
# CLI, and no bind-mount into host paths like /var/lib/containerd, and
# adding any of those for a disk-space warning would be a real security
# regression (root-equivalent host access) for a cosmetic UI check. So
# this threshold covers only the volumes location (verdix_models +
# verdix_data, ~12 GB measured): 15 GB minimum / 20 GB recommended, for
# pull/update headroom and DB/cache growth. A combined 30/40 GB figure
# would test something this check can't observe — it would report "ok"
# on a box where /var/lib/verdix's disk has plenty of room but the image
# store's disk is nearly full, which is a real, seen-in-the-field failure
# mode. The "Data volume free space" label (below) is deliberately narrow
# to match; DEPLOYMENT.md's storage section covers the image-store side,
# which this check cannot reach.
_DISK_MINIMUM_GB = 15
_DISK_RECOMMENDED_GB = 20


def _check_resources() -> list[CheckItem]:
    items: list[CheckItem] = []

    # RAM
    # _RAM_OK_GB sits below _RAM_RECOMMENDED_GB on purpose: OS-visible
    # MemTotal always reads a few percent under nominal DIMM capacity
    # (firmware/UEFI-reserved regions, ACPI tables, iGPU shared memory), so
    # a correctly provisioned 32 GB box routinely reports ~30 GB. Comparing
    # against the recommended figure with no tolerance false-warned on
    # hardware that met spec.
    mem = psutil.virtual_memory()
    total_gb = mem.total / (1024 ** 3)
    avail_gb = mem.available / (1024 ** 3)
    if total_gb >= _RAM_OK_GB:
        items.append(CheckItem(
            "Memory", "ok",
            f"{total_gb:.0f} GB total · {avail_gb:.0f} GB available",
        ))
    elif total_gb >= _RAM_MINIMUM_GB:
        items.append(CheckItem(
            "Memory", "warn",
            f"{total_gb:.0f} GB total — {_RAM_RECOMMENDED_GB} GB recommended "
            "for comfortable CPU inference",
        ))
    else:
        items.append(CheckItem(
            "Memory", "warn",
            f"{total_gb:.0f} GB total — minimum {_RAM_MINIMUM_GB} GB required; "
            f"{_RAM_RECOMMENDED_GB} GB recommended",
        ))

    # CPU
    cpu_count = psutil.cpu_count(logical=False) or psutil.cpu_count()
    avx2 = _has_avx2()
    avx_label = "AVX2 supported" if avx2 else "AVX2 not detected"
    if cpu_count and cpu_count >= 8 and avx2:
        items.append(CheckItem("CPU", "ok", f"{cpu_count} cores · {avx_label}"))
    elif cpu_count and cpu_count >= 4:
        items.append(CheckItem("CPU", "warn",
                               f"{cpu_count} cores · {avx_label} — 8+ cores recommended"))
    else:
        items.append(CheckItem("CPU", "warn",
                               f"{cpu_count or '?'} cores · {avx_label}"))

    # GPU
    gpu_detail = _detect_gpu()
    if gpu_detail:
        vram_gb = gpu_detail.get("vram_gb", 0)
        name = gpu_detail.get("name", "GPU")
        if vram_gb >= 12:
            items.append(CheckItem(
                "GPU (optional)", "ok",
                f"{name} · {vram_gb:.0f} GB VRAM · GPU acceleration active (~30s per verdict)",
            ))
        else:
            items.append(CheckItem(
                "GPU (optional)", "info",
                f"{name} · {vram_gb:.0f} GB VRAM — insufficient VRAM for full offload "
                "(12 GB+ needed); falling back to CPU speed (~120–180s per verdict)",
            ))
    else:
        items.append(CheckItem(
            "GPU (optional)", "info",
            "No GPU detected — running on CPU (~120–180s per verdict). "
            "Add a GPU with 12 GB+ VRAM for ~30s verdicts.",
        ))

    # Disk
    # This measures free space on VX_DATA_PATH's filesystem only — the
    # verdix_data volume (SQLite DB, GeoIP files, enrichment cache). It
    # cannot see Docker's image/layer store or the verdix_models volume,
    # which can live on a different filesystem entirely if Docker's
    # data-root has been relocated (see DEPLOYMENT.md's "Moving Docker
    # storage" section) — check those separately in that case.
    data_path = os.environ.get("VX_DATA_PATH", "/var/lib/verdix")
    try:
        disk = psutil.disk_usage(data_path if os.path.exists(data_path) else "/")
        free_gb = disk.free / (1024 ** 3)
        if free_gb >= _DISK_RECOMMENDED_GB:
            items.append(CheckItem("Data volume free space", "ok", f"{free_gb:.0f} GB free"))
        elif free_gb >= _DISK_MINIMUM_GB:
            items.append(CheckItem(
                "Data volume free space", "warn",
                f"{free_gb:.0f} GB free — {_DISK_RECOMMENDED_GB} GB recommended",
            ))
        else:
            items.append(CheckItem(
                "Data volume free space", "warn",
                f"{free_gb:.0f} GB free — minimum {_DISK_MINIMUM_GB} GB required; "
                f"free up space or expand the Docker volume",
            ))
    except Exception:  # noqa: BLE001
        items.append(CheckItem("Data volume free space", "info", "Unable to read disk usage"))

    return items


def _has_avx2() -> bool:
    if platform.system() == "Linux":
        try:
            with open("/proc/cpuinfo") as f:
                return "avx2" in f.read()
        except OSError:
            return False
    # Windows/macOS: assume modern hardware
    return True


def _detect_gpu() -> dict[str, Any] | None:
    try:
        out = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=name,memory.total",
             "--format=csv,noheader,nounits"],
            timeout=5, stderr=subprocess.DEVNULL, text=True,
        )
        line = out.strip().splitlines()[0]
        name, vram_mb = line.rsplit(",", 1)
        return {"name": name.strip(), "vram_gb": float(vram_mb.strip()) / 1024}
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# Network checks
# ---------------------------------------------------------------------------

def _check_network() -> list[CheckItem]:
    items: list[CheckItem] = []

    http_proxy = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
    https_proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    no_proxy = os.environ.get("NO_PROXY") or os.environ.get("no_proxy", "")

    if https_proxy or http_proxy:
        proxy = https_proxy or http_proxy
        # Redact credentials from display
        display = _redact_proxy(proxy)
        items.append(CheckItem("Proxy", "ok", f"{display} · Configured"))

        # Check NO_PROXY includes internal services
        no_proxy_vals = [v.strip() for v in no_proxy.split(",")]
        missing = [s for s in ("localhost", "llm") if s not in no_proxy_vals]
        if missing:
            items.append(CheckItem(
                "NO_PROXY exclusions", "warn",
                f"HTTPS_PROXY is set but NO_PROXY does not exclude internal services — "
                f"add {', '.join(missing)} to NO_PROXY",
            ))
        else:
            items.append(CheckItem(
                "NO_PROXY exclusions", "ok",
                f"localhost and llm excluded from proxy",
            ))
    else:
        items.append(CheckItem("Proxy", "info", "No proxy configured (direct connection)"))

    return items


def _redact_proxy(url: str) -> str:
    import re
    return re.sub(r"(https?://)([^@]+@)?", lambda m: m.group(1) + ("***:***@" if m.group(2) else ""), url)


# ---------------------------------------------------------------------------
# Enrichment checks
# ---------------------------------------------------------------------------

async def _check_enrichment() -> list[CheckItem]:
    items: list[CheckItem] = []

    # VirusTotal
    if os.environ.get("VX_VIRUSTOTAL_API_KEY"):
        items.append(CheckItem("VirusTotal", "ok", "API key configured"))
    else:
        items.append(CheckItem(
            "VirusTotal", "info",
            "Not configured — set VX_VIRUSTOTAL_API_KEY to enable reputation lookups",
        ))

    # GeoIP
    country_db = os.environ.get("VX_GEOIP_COUNTRY_DB_PATH", "")
    asn_db = os.environ.get("VX_GEOIP_ASN_DB_PATH", "")
    if country_db and os.path.isfile(country_db) and asn_db and os.path.isfile(asn_db):
        items.append(CheckItem("GeoIP / ASN", "ok", "Database files loaded"))
    elif country_db or asn_db:
        items.append(CheckItem(
            "GeoIP / ASN", "warn",
            "VX_GEOIP_COUNTRY_DB_PATH or VX_GEOIP_ASN_DB_PATH points to a missing file",
        ))
    else:
        items.append(CheckItem(
            "GeoIP / ASN", "info",
            "Not configured — set VX_GEOIP_COUNTRY_DB_PATH and VX_GEOIP_ASN_DB_PATH",
        ))

    # RDAP
    rdap_item = await _check_rdap()
    items.append(rdap_item)

    # Reverse DNS
    revdns_enabled = os.environ.get("VX_REVDNS_ENABLED", "true").lower() not in ("false", "0", "no")
    dns_server = os.environ.get("VX_DNS_SERVER", "")
    if not revdns_enabled:
        items.append(CheckItem("Reverse DNS", "info", "Disabled (VX_REVDNS_ENABLED=false)"))
    elif dns_server:
        items.append(CheckItem(
            "Reverse DNS", "ok",
            f"Enabled - resolver: {dns_server}",
        ))
    else:
        items.append(CheckItem(
            "Reverse DNS", "ok",
            "Enabled - using system DNS resolver",
        ))

    return items


async def _check_rdap() -> CheckItem:
    from src.infra.http.factory import create_http_client

    try:
        async with create_http_client(8.0, "rdap") as client:
            resp = await client.get("https://data.iana.org/rdap/dns.json")
        if resp.status_code == 200:
            return CheckItem("RDAP (domain age)", "ok", "Registry reachable")
        return CheckItem(
            "RDAP (domain age)", "warn",
            f"IANA RDAP registry returned HTTP {resp.status_code}",
        )
    except Exception:  # noqa: BLE001
        return CheckItem(
            "RDAP (domain age)", "warn",
            "Cannot reach IANA RDAP registry — domain age lookups will degrade gracefully",
        )
