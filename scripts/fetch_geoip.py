# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Fetch DB-IP Community Edition GeoIP databases into geoip/.

The Dockerfile's `COPY geoip/ /var/lib/verdix/geoip/` is unconditional, and
geoip/*.mmdb is gitignored, so a clean clone cannot build the app image until
this has run once. Both CI (.github/workflows/release.yml, build-app job) and
a local build call this same script, so the fetch logic lives in exactly one
place instead of being duplicated in a YAML file only CI reads.

Stdlib-only on purpose: a contributor who hasn't run `pip install` yet still
needs this to work, on any of Windows, macOS, or Linux, with no WSL or shell
script required.

Usage:
    python scripts/fetch_geoip.py
"""
from __future__ import annotations

import datetime
import gzip
import shutil
import sys
import urllib.error
import urllib.request
from pathlib import Path

DBIP_BASE_URL = "https://download.db-ip.com/free"
GEOIP_DIR = Path(__file__).resolve().parent.parent / "geoip"
DATABASES = ("dbip-country-lite", "dbip-asn-lite")


def _candidate_months() -> list[tuple[int, int]]:
    """This month, then last month.

    DB-IP publishes one file per calendar month and retires old ones after a
    delay. Early in the month, the current month's file may not be up yet, so
    fall back to last month's rather than failing outright.
    """
    today = datetime.date.today()
    months = [(today.year, today.month)]
    if today.month == 1:
        months.append((today.year - 1, 12))
    else:
        months.append((today.year, today.month - 1))
    return months


def _fetch_one(name: str) -> None:
    dest = GEOIP_DIR / f"{name}.mmdb"
    errors: list[str] = []
    for year, month in _candidate_months():
        url = f"{DBIP_BASE_URL}/{name}-{year:04d}-{month:02d}.mmdb.gz"
        print(f"Fetching {url}")
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "verdix-fetch-geoip"})
            with urllib.request.urlopen(request, timeout=30) as response:
                with gzip.GzipFile(fileobj=response) as gz, dest.open("wb") as out:
                    shutil.copyfileobj(gz, out)
        except urllib.error.HTTPError as exc:
            errors.append(f"{url} -> HTTP {exc.code}")
            continue
        print(f"  wrote {dest} ({dest.stat().st_size:,} bytes)")
        return
    raise SystemExit(
        f"Could not fetch {name}: every candidate month failed.\n" + "\n".join(errors)
    )


def main() -> int:
    GEOIP_DIR.mkdir(exist_ok=True)
    for name in DATABASES:
        _fetch_one(name)
    print(f"GeoIP databases ready in {GEOIP_DIR}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
