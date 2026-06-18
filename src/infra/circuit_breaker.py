# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Lightweight async-native circuit breaker.

pybreaker's call_async() requires Tornado. Since this project uses asyncio
exclusively, this module provides a minimal state-machine CB that is compatible
with asyncio coroutines without additional dependencies.

Used by:
  - ReverseDNSIdentityProvider (Days 7-8)
  - Enrichment clients: VirusTotal, RDAP, MaxMind (Days 8-10)

States:
  CLOSED   — normal operation; failures are counted
  OPEN     — short-circuit: raise CircuitBreakerOpen without calling the func
  HALF_OPEN — one probe request allowed; success → CLOSED, failure → OPEN again
"""
from __future__ import annotations

import asyncio
import enum
import time
from collections.abc import Awaitable, Callable
from typing import Any, TypeVar

T = TypeVar("T")


class _State(enum.Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerOpen(Exception):
    """Raised when the circuit breaker is open and a call is attempted."""


class AsyncCircuitBreaker:
    """Async-native circuit breaker.

    Args:
        fail_max:      Number of consecutive failures before the circuit opens.
        reset_timeout: Seconds to wait in OPEN state before attempting a probe.
    """

    def __init__(self, *, fail_max: int = 5, reset_timeout: float = 60.0) -> None:
        self._fail_max = fail_max
        self._reset_timeout = reset_timeout
        self._state = _State.CLOSED
        self._failures = 0
        self._opened_at: float = 0.0
        self._lock = asyncio.Lock()  # serialises state-machine transitions

    @property
    def state(self) -> str:
        return self._state.value

    def _check_reset(self) -> None:
        if self._state is _State.OPEN:
            if time.monotonic() - self._opened_at >= self._reset_timeout:
                self._state = _State.HALF_OPEN

    async def call(
        self,
        func: Callable[..., Awaitable[T]],
        *args: Any,
        **kwargs: Any,
    ) -> T:
        """Call func if the circuit allows it; raise CircuitBreakerOpen if not.

        The lock is held only around state-machine reads/writes, not during the
        actual awaited call — so concurrent callers are not serialised by the CB.
        """
        async with self._lock:
            self._check_reset()
            if self._state is _State.OPEN:
                raise CircuitBreakerOpen(
                    f"Circuit breaker open (failures={self._failures})"
                )
        try:
            result = await func(*args, **kwargs)
            async with self._lock:
                self._on_success()
            return result
        except Exception:
            async with self._lock:
                self._on_failure()
            raise

    def _on_success(self) -> None:
        self._failures = 0
        self._state = _State.CLOSED

    def _on_failure(self) -> None:
        self._failures += 1
        if self._failures >= self._fail_max or self._state is _State.HALF_OPEN:
            self._state = _State.OPEN
            self._opened_at = time.monotonic()
