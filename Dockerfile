# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
# Verdix — Application image
# Build:  docker build -t verdix/app:0.1.0 .
# Run:    see docker-compose.yml

FROM python:3.13-slim

# libgomp1 is required by the geoip2 MMDB reader (OpenMP dependency).
# gosu lets the entrypoint start as root (to fix bind-mount group
# permissions), then drop to appuser without leaving a supervisor process
# running as root — see entrypoint.sh.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 gosu \
    && rm -rf /var/lib/apt/lists/*

# Non-root user and persistent-state directory.
RUN useradd -u 1000 -m -s /bin/bash appuser \
    && mkdir -p /var/lib/verdix/geoip \
    && chown -R appuser:appuser /var/lib/verdix

WORKDIR /app

# Install Python dependencies before copying source so this layer is cached
# even when only source files change.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Application source, Alembic migrations, and project metadata.
COPY pyproject.toml alembic.ini ./
COPY alembic/ alembic/
COPY src/ src/

# DB-IP Community Edition GeoIP databases (CC BY 4.0 — db-ip.com).
# Copies the full geoip/ directory, then creates stable symlinks at the paths
# the application expects. DB-IP names monthly releases with a date suffix
# (dbip-country-lite-YYYY-MM.mmdb); this handles both that format and plain
# unversioned filenames so the build works on any machine.
COPY geoip/ /var/lib/verdix/geoip/
RUN cd /var/lib/verdix/geoip && \
    if [ ! -f dbip-country-lite.mmdb ]; then \
        ln -sf "$(ls dbip-country-lite-*.mmdb 2>/dev/null | sort -r | head -1)" dbip-country-lite.mmdb; \
    fi && \
    if [ ! -f dbip-asn-lite.mmdb ]; then \
        ln -sf "$(ls dbip-asn-lite-*.mmdb 2>/dev/null | sort -r | head -1)" dbip-asn-lite.mmdb; \
    fi

RUN chown -R appuser:appuser /var/lib/verdix

# Entrypoint fixes bind-mount group permissions (see entrypoint.sh), then
# execs into appuser — no application code ever runs as root. The image
# stays without a USER directive so the entrypoint can start as root; the
# actual running process is always appuser (uid 1000) once ENTRYPOINT
# execs, which is what `docker top` / `ps` inside the container will show.
# Note: this means the image's *declared* USER is root, which trips
# Kubernetes' `securityContext.runAsNonRoot: true` if this is ever deployed
# there — not a concern for Docker Compose (v0.1's only packaging target).
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "-m", "src.main"]
