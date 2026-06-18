# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""VirusTotal client-side rate limiter — 4 requests per minute (free tier).

Implemented as an async token bucket. Cache hits bypass this entirely;
only live HTTP calls consume tokens.

tenacity is used for the wait logic, matching the project's existing retry dependency.
"""
from __future__ import annotations

import asyncio
import time


class RateLimiter:
    """Async token bucket: `rate` tokens per `period` seconds.

    Args:
        rate:   Max requests allowed in the period (default 4 for VT free tier).
        period: Time window in seconds (default 60).
    """

    def __init__(self, *, rate: int = 4, period: float = 60.0) -> None:
        self._rate = rate
        self._period = period
        self._tokens = float(rate)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Block until a token is available."""
        async with self._lock:
            while True:
                now = time.monotonic()
                elapsed = now - self._last_refill
                # Refill tokens proportionally to elapsed time.
                self._tokens = min(
                    float(self._rate),
                    self._tokens + elapsed * (self._rate / self._period),
                )
                self._last_refill = now

                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return

                # Sleep until at least one token is available.
                deficit = 1.0 - self._tokens
                wait = deficit * (self._period / self._rate)
                await asyncio.sleep(wait)
