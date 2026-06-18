# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Ollama HTTP client — implements LLMProvider for the local Ollama container.

Default base URL is http://llm:11434/api/chat which matches the docker-compose
service name. Override via the base_url constructor argument when running outside
Docker (e.g. eval harness: http://localhost:11434/api/chat).

Uses Ollama's structured output (format="json" + JSON schema) and requests
num_ctx=8192 — Ollama's default of 4096 is insufficient for complex alerts.

Retry logic: up to 3 attempts on parse failure, with a corrective follow-up
prompt on each retry. Tracks first_attempt_valid and total attempts for
structured-output reliability metrics (target: >99% valid on first attempt).
"""
from __future__ import annotations

import os
import time
from typing import Any

import structlog

from src.infra.http.factory import create_http_client
from src.llm.models import LLMResponse, VerdictOutput

_DEFAULT_BASE_URL = "http://llm:11434/api/chat"
_DEFAULT_MODEL = "gemma4:e4b-it-q8_0"

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
    """

    OUTPUT_SCHEMA: dict[str, Any] = _OUTPUT_SCHEMA

    def __init__(
        self,
        model: str = _DEFAULT_MODEL,
        base_url: str = _DEFAULT_BASE_URL,
        timeout: float = 300.0,
        temperature: float | None = None,
    ) -> None:
        self._model = model
        self.base_url = base_url
        self.timeout = timeout
        self._temperature = temperature

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

        Retries up to 3 times on parse failure. Never raises for recoverable
        failures — raises RuntimeError only when all 3 attempts fail.
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

        for attempt in range(1, 4):
            try:
                raw = await self._single_call(current_prompt, output_schema)
                output = VerdictOutput.model_validate_json(raw)
                return output, attempt, (attempt == 1)
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                # Corrective follow-up prompt for retry: append the raw
                # (invalid) response and ask the model to fix it.
                if attempt < 3:
                    try:
                        raw_preview = raw[:200] if "raw" in dir() else "(no output)"
                    except Exception:  # noqa: BLE001
                        raw_preview = "(no output)"
                    current_prompt = (
                        f"{prompt}\n\n"
                        f"Your previous response was invalid JSON. "
                        f"It started with: {raw_preview}\n"
                        f"Please return ONLY valid JSON matching the schema. "
                        f"No preamble, no markdown fences."
                    )

        raise RuntimeError(
            f"All 3 Ollama attempts failed. Last error: {last_error}"
        ) from last_error

    async def _single_call(self, prompt: str, output_schema: dict[str, Any]) -> str:
        if _LOG_LLM_IO:
            logger.info("llm_prompt_sent", model=self._model, prompt=prompt)
        options: dict[str, Any] = {"num_ctx": 8192}
        if self._temperature is not None:
            # Pin greedy decoding. Both the product (temperature 0, deterministic
            # verdicts) and the eval harness set this explicitly; only an unset
            # default (None) omits the key. 0.0 is intentional, hence the explicit
            # `is not None` check rather than a truthiness test.
            options["temperature"] = self._temperature
        payload = {
            "model": self._model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "format": output_schema,
            "options": options,
        }
        async with create_http_client(self.timeout, "ollama") as client:
            response = await client.post(self.base_url, json=payload)
            response.raise_for_status()
            data = response.json()
            content = data["message"]["content"]
        if _LOG_LLM_IO:
            logger.info("llm_response_received", model=self._model, response=content)
        return content
