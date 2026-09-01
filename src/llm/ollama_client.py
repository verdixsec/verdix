# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Ollama HTTP client — implements LLMProvider for the local Ollama container.

Default base URL is http://llm:11434/api/chat which matches the docker-compose
service name. Override via the base_url constructor argument when running outside
Docker (e.g. eval harness: http://localhost:11434/api/chat).

Uses Ollama's structured output (format="json" + JSON schema) and requests
num_ctx=8192 — Ollama's default of 4096 is insufficient for complex alerts.
Sends think=false: measured on ramon (docs/progress.md session 73, continued)
at 79% shorter generation time with an identical decode rate, category verdict
unaffected across all sampled runs.

Retry logic: up to 2 attempts total on parse failure, with a corrective
follow-up prompt on the retry. A read timeout is never retried (no response
was returned to correct, and a second attempt at VX_OLLAMA_TIMEOUT_SECONDS
doubles the worst-case wall clock for nothing). Tracks first_attempt_valid
and total attempts for structured-output reliability metrics (target: >99%
valid on first attempt).
"""
from __future__ import annotations

import os
import time
from typing import Any

import structlog
from pydantic import ValidationError

from src.infra.http.factory import create_http_client
from src.llm.models import LLMResponse, VerdictOutput

_DEFAULT_BASE_URL = "http://llm:11434/api/chat"
_DEFAULT_MODEL = "gemma4:e4b-it-q8_0"
_MAX_ATTEMPTS = 2

# Set VX_LOG_LLM_PROMPTS=1 in .env to emit the full prompt and raw LLM response
# to stdout at INFO level — useful for debugging prompt truncation / quality issues.
# Does not require VX_LOG_LEVEL=DEBUG (avoids noisy global debug output).
_LOG_LLM_IO = os.environ.get("VX_LOG_LLM_PROMPTS", "").lower() in ("1", "true", "yes")

logger = structlog.get_logger(__name__)

# JSON schema sent to Ollama structured output. Exposed as a class attribute
# so callers (eval harness, triage worker) can reference the canonical schema.
_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "verdict_category": {
            "type": "string",
            "enum": ["likely_fp", "suspicious_investigate", "likely_tp"],
        },
        "confidence_score": {"type": "number"},
        "reasoning": {"type": "string"},
        "contributing_facts": {
            "type": "array",
            "items": {"type": "string"},
        },
    },
    "required": ["verdict_category", "confidence_score", "reasoning", "contributing_facts"],
}

# Corrective follow-up prompt sent on the one retry, when the first response
# failed JSON/schema validation. Kept as fixed literal strings (only the
# 200-char failure preview is interpolated) so a later edit can't silently
# weaken the wording without a test noticing.
_CORRECTIVE_PREAMBLE = (
    "Your previous response could not be parsed as valid JSON matching the "
    "required schema. It started with: "
)
_CORRECTIVE_SCHEMA_RESTATEMENT = (
    "\n\nReturn ONLY a single JSON object with exactly these fields:\n"
    '- verdict_category: string, one of "likely_fp", "suspicious_investigate", "likely_tp"\n'
    "- confidence_score: number between 0.0 and 1.0\n"
    "- reasoning: a concise string (a few sentences, not a full essay)\n"
    "- contributing_facts: a concise array of short strings\n"
    "No preamble, no markdown fences, no text outside the JSON object."
)


def _build_corrective_prompt(original_prompt: str, failed_raw: str) -> str:
    """Build the retry prompt after a JSON/schema validation failure.

    Appends only a 200-char preview of the failed response, not the full
    text — this is a deliberate context-budget control against num_ctx=8192,
    not an artifact of the single-turn shape. See ADR discussion in the
    session that introduced this: reworking into a genuine multi-turn
    payload would require a token-aware cap of its own; the character slice
    already does that job.
    """
    preview = failed_raw[:200]
    return f"{original_prompt}\n\n{_CORRECTIVE_PREAMBLE}{preview}{_CORRECTIVE_SCHEMA_RESTATEMENT}"


def _classify_request_exception(exc: Exception) -> tuple[str, bool]:
    """Classify an exception raised while calling Ollama, without importing
    httpx directly (ruff TID251 bans it outside src/infra/http/ — matches the
    qualname-substring pattern already used in
    src/enrichment/virustotal/client.py:_fetch).

    Returns (failure_class, retryable).
    """
    etype = type(exc).__qualname__

    if "Timeout" in etype:
        # ReadTimeout / ConnectTimeout / WriteTimeout / PoolTimeout /
        # TimeoutException: no response came back to correct against, and a
        # second attempt costs another full VX_OLLAMA_TIMEOUT_SECONDS window.
        return "read_timeout", False

    if "ConnectError" in etype:
        # Transient -- e.g. the llm container restarting.
        return "connect_error", True

    if "HTTPStatusError" in etype:
        status_code = getattr(getattr(exc, "response", None), "status_code", None)
        # 503: Ollama still starting up -- transient, worth the one retry.
        # Anything else (in particular 500): a real server-side defect, not a
        # transient condition -- session 70 saw 22+ consecutive HTTP 500s from
        # a memory-discovery bug where retrying never succeeded and only
        # doubled time-to-diagnosis. Fail immediately instead.
        return "http_error", status_code == 503

    # Anything not explicitly classified above (KeyError from an unexpected
    # response shape, a raw JSON decode failure on the outer HTTP body, other
    # httpx transport errors). Retryable, matching the prior blanket-catch
    # behaviour for the genuinely-unanticipated case -- but always logged, per
    # "keep a final except Exception fallback, but make it the last branch."
    return "unclassified", True


class OllamaClient:
    """Async client around Ollama /api/chat — implements LLMProvider.

    Args:
        model:    Ollama model tag. Default: gemma4:e4b-it-q8_0 (validated by
                  eval harness in week 1 as the best accuracy/latency tradeoff).
        base_url: Ollama API endpoint. Default: http://llm:11434/api/chat
                  (docker-compose service name). Use http://localhost:11434/...
                  when running outside Docker (eval harness, local dev).
        timeout:  Per-request HTTP timeout in seconds.
        temperature: Optional Ollama sampling temperature. Default None leaves
                  the key out of the request options entirely, so the model's
                  own default applies. Both the eval harness and the product
                  pass an explicit value: the product pins 0 for deterministic
                  verdicts (matching the validated temp=0 baseline), and the
                  eval harness passes temperature=0 for greedy/reproducible
                  decoding.
        num_thread: Optional Ollama thread-pool size. Default None leaves the
                  key out of the request options, so Ollama sizes the pool from
                  the host's visible physical cores -- which collapses
                  throughput on any host where the allowed CPUs (cgroup mask,
                  Docker --cpus, k8s limit) are fewer than the visible core
                  count (PROGRESS.md item 45). Pass the host's actual allowed
                  core count explicitly on such a host (ramon: 16, item 47).
    """

    OUTPUT_SCHEMA: dict[str, Any] = _OUTPUT_SCHEMA

    def __init__(
        self,
        model: str = _DEFAULT_MODEL,
        base_url: str = _DEFAULT_BASE_URL,
        timeout: float = 300.0,
        temperature: float | None = None,
        num_thread: int | None = None,
    ) -> None:
        self._model = model
        self.base_url = base_url
        self.timeout = timeout
        self._temperature = temperature
        self._num_thread = num_thread

    @property
    def model_version(self) -> str:
        """Model identifier persisted in every verdict row for provenance."""
        return self._model

    async def complete(
        self,
        prompt: str,
        output_schema: dict[str, Any],
        *,
        prompt_version: str = "unknown",
    ) -> LLMResponse:
        """Send prompt to Ollama and return a structured verdict response.

        Retries once on parse failure (2 attempts total). Never raises for a
        recoverable parse/connect failure until attempts are exhausted — but
        raises immediately, without retrying, on a read timeout or a
        degenerate (truncated-for-length / empty) response.
        """
        t0 = time.monotonic()
        output, attempts, first_attempt_valid = await self._call_with_retry(
            prompt, output_schema
        )
        latency_ms = int((time.monotonic() - t0) * 1000)

        return LLMResponse(
            verdict_category=output.verdict_category,
            confidence_score=output.confidence_score,
            reasoning=output.reasoning,
            contributing_facts=output.contributing_facts,
            raw_output=output.model_dump(),
            latency_ms=latency_ms,
            model_version=self._model,
            prompt_version=prompt_version,
            first_attempt_valid=first_attempt_valid,
            attempts=attempts,
            llm_inputs={"prompt": prompt, "output_schema": output_schema},
        )

    async def _call_with_retry(
        self, prompt: str, output_schema: dict[str, Any]
    ) -> tuple[VerdictOutput, int, bool]:
        last_error: Exception | None = None
        current_prompt = prompt

        for attempt in range(1, _MAX_ATTEMPTS + 1):
            try:
                raw, done_reason = await self._single_call(current_prompt, output_schema)
            except Exception as exc:  # noqa: BLE001
                failure_class, retryable = _classify_request_exception(exc)
                status_code = getattr(getattr(exc, "response", None), "status_code", None)

                if failure_class == "read_timeout":
                    logger.error(
                        "llm_read_timeout",
                        attempt=attempt,
                        timeout_seconds=self.timeout,
                    )
                    raise

                if not retryable:
                    logger.warning(
                        "llm_retry_skipped",
                        attempt=attempt,
                        reason="http_not_retryable",
                        status_code=status_code,
                    )
                    raise

                last_error = exc
                logger.warning(
                    "llm_retry_attempt",
                    attempt=attempt,
                    failure_class=failure_class,
                    status_code=status_code,
                )
                if attempt < _MAX_ATTEMPTS:
                    # Nothing to correct -- resend the original prompt unchanged.
                    current_prompt = prompt
                    continue
                logger.error(
                    "llm_retry_exhausted",
                    attempts=attempt,
                    last_failure_class=failure_class,
                )
                raise RuntimeError(
                    f"All {_MAX_ATTEMPTS} Ollama attempts failed. Last error: {last_error}"
                ) from last_error

            if done_reason == "length" or not raw.strip():
                # Retrying at the same num_ctx will truncate the same way again.
                logger.warning(
                    "llm_retry_skipped",
                    attempt=attempt,
                    reason="degenerate_response",
                    done_reason=done_reason,
                    response_len=len(raw),
                )
                raise RuntimeError(
                    f"Ollama returned a degenerate response "
                    f"(done_reason={done_reason!r}, response_len={len(raw)}); not retrying."
                )

            try:
                output = VerdictOutput.model_validate_json(raw)
                return output, attempt, (attempt == 1)
            except ValidationError as exc:
                last_error = exc
                errors = exc.errors()
                failure_class = (
                    "json_invalid"
                    if errors and errors[0].get("type") == "json_invalid"
                    else "schema_invalid"
                )
                logger.warning(
                    "llm_retry_attempt",
                    attempt=attempt,
                    failure_class=failure_class,
                    response_len=len(raw),
                )
                if attempt < _MAX_ATTEMPTS:
                    current_prompt = _build_corrective_prompt(prompt, raw)
                    continue
                logger.error(
                    "llm_retry_exhausted",
                    attempts=attempt,
                    last_failure_class=failure_class,
                )
                raise RuntimeError(
                    f"All {_MAX_ATTEMPTS} Ollama attempts failed. Last error: {last_error}"
                ) from last_error

        # Unreachable (the loop always returns or raises), kept for mypy.
        raise RuntimeError(
            f"All {_MAX_ATTEMPTS} Ollama attempts failed. Last error: {last_error}"
        ) from last_error

    async def _single_call(
        self, prompt: str, output_schema: dict[str, Any]
    ) -> tuple[str, str | None]:
        """Send one request to Ollama. Returns (content, done_reason).

        done_reason is Ollama's own completion-reason field (e.g. "stop",
        "length") — read so the caller can treat a length-truncated response
        as non-retryable rather than as an ordinary parse failure.
        """
        if _LOG_LLM_IO:
            logger.info("llm_prompt_sent", model=self._model, prompt=prompt)
        options: dict[str, Any] = {"num_ctx": 8192}
        if self._temperature is not None:
            # Pin greedy decoding. Both the product (temperature 0, deterministic
            # verdicts) and the eval harness set this explicitly; only an unset
            # default (None) omits the key. 0.0 is intentional, hence the explicit
            # `is not None` check rather than a truthiness test.
            options["temperature"] = self._temperature
        if self._num_thread is not None:
            options["num_thread"] = self._num_thread
        payload = {
            "model": self._model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "format": output_schema,
            "think": False,
            "options": options,
        }
        async with create_http_client(self.timeout, "ollama") as client:
            response = await client.post(self.base_url, json=payload)
            response.raise_for_status()
            data = response.json()
            content = data["message"]["content"]
            done_reason = data.get("done_reason")
        if _LOG_LLM_IO:
            logger.info("llm_response_received", model=self._model, response=content)
        return content, done_reason
