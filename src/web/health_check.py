# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""System health introspection for the /api/health endpoint and Setup screen.

Checks are grouped into four categories matching the design:
  - core:        eve.json, admin password, Ollama
  - resources:   RAM, CPU, GPU (optional), disk
  - network:     proxy configuration
  - enrichment:  VirusTotal, GeoIP, RDAP (all optional)

run_health_check() is async and performs live I/O (Ollama ping, RDAP probe).
All failures are caught and reported as check items — never raises.
"""
from __future__ import annotations

import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any

import psutil


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
            "all_required_ok": self.all_required_ok,
        }


async def run_health_check() -> HealthResult:
    result = HealthResult()
    result.core = await _check_core()
    result.resources = _check_resources()
    result.network = _check_network()
    result.enrichment = await _check_enrichment()
    return result


# ---------------------------------------------------------------------------
# Core checks
# ---------------------------------------------------------------------------

async def _check_core() -> list[CheckItem]:
    items: list[CheckItem] = []

    # eve.json
    eve_path = os.environ.get("VX_EVE_LOG_PATH", "/host/suricata/logs/eve.json")
    if os.path.isfile(eve_path) and os.access(eve_path, os.R_OK):
        items.append(CheckItem("Alert log (eve.json)", "ok",
                               f"Found at {eve_path}", required=True))
    else:
        items.append(CheckItem(
            "Alert log (eve.json)", "error",
            f"Not found at {eve_path} — update the bind mount path in "
            "docker-compose.yml and restart",
            required=True,
        ))

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
    import httpx
    from urllib.parse import urlparse, urlunparse

    ollama_url = os.environ.get("VX_OLLAMA_URL", "http://llm:11434/api/chat")
    default_model = os.environ.get("VX_OLLAMA_MODEL", "gemma4:e4b-it-q8_0")
    # SC_OLLAMA_URL is the full chat endpoint (e.g. http://host:11434/api/chat).
    # Strip the path to get the base URL for the tags probe.
    parsed = urlparse(ollama_url)
    base_url = urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))
    tags_url = f"{base_url}/api/tags"

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
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
    except httpx.ConnectError:
        return CheckItem(
            "AI Engine (Ollama)", "error",
            f"Cannot reach Ollama at {ollama_url} — is the llm container running?",
        )
    except Exception as exc:  # noqa: BLE001
        return CheckItem("AI Engine (Ollama)", "error", f"Unexpected error: {exc}")


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
    import httpx

    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
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
