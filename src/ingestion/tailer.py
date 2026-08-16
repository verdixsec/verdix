# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""EVE JSON file tailer — polls eve.json and emits EveEvent objects to an async queue.

Tails from end-of-file on startup (no history replay). Handles log rotation via
inode comparison on POSIX or file-size regression on Windows/NFS where st_ino is 0.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import structlog

from src.ingestion.models import EveEvent
from src.ingestion.status import IngestionStatus

logger = structlog.get_logger(__name__)


class EveTailer:
    """Polls eve.json and emits parsed EveEvent objects to an async queue.

    Args:
        eve_path:        Path to eve.json (local or NFS/SMB mount — both look identical).
        queue:           Destination queue; shared with the broadcaster.
        poll_interval_ms: How often to check for new bytes. Default 500ms per ADR-001.
        status:          Shared IngestionStatus (ADR-019). Defaults to a private
                          instance when not supplied, so callers that don't care
                          about live status (e.g. most tests) don't need to pass one.
    """

    def __init__(
        self,
        eve_path: str | Path,
        queue: asyncio.Queue[EveEvent],
        *,
        poll_interval_ms: int = 500,
        status: IngestionStatus | None = None,
    ) -> None:
        self._path = Path(eve_path)
        self._queue = queue
        self._status = status if status is not None else IngestionStatus(poll_interval_ms)
        self._position: int = 0
        self._inode: int = 0

    async def run(self) -> None:
        """Tail eve.json until cancelled.

        Raises FileNotFoundError immediately if the path does not exist at startup —
        the application should fail fast rather than silently produce no alerts.
        """
        if not self._path.exists():
            raise FileNotFoundError(f"EVE log not found: {self._path}")

        stat = self._path.stat()
        self._position = stat.st_size  # start at end — no history replay
        self._inode = stat.st_ino

        logger.info("eve_tailer_started", path=str(self._path), position=self._position)
        try:
            while True:
                await asyncio.sleep(self._status.retry_interval_s)
                await self._poll()
        except asyncio.CancelledError:
            logger.info("eve_tailer_stopped", path=str(self._path))
            raise

    async def _poll(self) -> None:
        """Check for new bytes or rotation, then read any new lines."""
        try:
            stat = self._path.stat()
        except FileNotFoundError:
            return  # rotation in progress; wait for file to reappear — not a failure
        except OSError as exc:
            # e.g. PermissionError: the mount is visible but no longer readable
            # (the 2026-08-12 mechanism). Unlike FileNotFoundError this is a
            # real failure and must count toward the retry/red-status schedule.
            self._on_failure(exc)
            return

        # Rotation: inode changed (POSIX) or file smaller than our position (all platforms).
        # st_ino is 0 on Windows NTFS for most files, so we always check size too.
        inode_changed = stat.st_ino != 0 and stat.st_ino != self._inode
        size_regressed = stat.st_size < self._position
        if inode_changed or size_regressed:
            logger.info("eve_tailer_rotation_detected", path=str(self._path))
            self._position = 0
            self._inode = stat.st_ino

        # Always attempt the read — on SMB/NFS mounts stat.st_size can be stale
        # due to client-side metadata caching, so we cannot use it as a skip guard.
        # Reading past EOF is safe: iteration yields nothing and position is unchanged.
        await self._read_new_lines()

    async def _read_new_lines(self) -> None:
        """Read from current position to EOF, parse JSON, enqueue valid events.

        Opens the file fresh on every call rather than holding a descriptor
        across polls, so recovery from a permission change does not depend on
        a file handle that survived it.
        """
        try:
            with self._path.open("r", encoding="utf-8", errors="replace") as fh:
                fh.seek(self._position)
                for raw_line in fh:
                    line = raw_line.rstrip("\n")
                    if not line:
                        continue
                    try:
                        data: dict[str, Any] = json.loads(line)
                    except json.JSONDecodeError:
                        logger.warning("eve_tailer_parse_error", line_preview=line[:120])
                        continue
                    await self._queue.put(EveEvent.from_dict(data))
                self._position = fh.tell()
        except OSError as exc:
            self._on_failure(exc)
            return
        self._on_success()

    def _on_failure(self, exc: Exception) -> None:
        # Per-attempt detail at debug — a transient blip that recovers before
        # the red threshold would otherwise leave no trace at all.
        logger.debug("eve_tailer_read_error", error=str(exc))
        if self._status.record_failure(exc):
            logger.error("eve_tailer_status_red", error=str(exc))

    def _on_success(self) -> None:
        if self._status.record_success():
            logger.info("eve_tailer_status_green")
