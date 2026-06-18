# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Google Gemini client via AI Studio REST API — implements LLMProvider.

Used by the eval harness for cross-model comparison (Gemini vs local Gemma).
Not used in the production triage pipeline (production uses OllamaClient).
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

from src.infra.http.factory import create_http_client
from src.llm.models import LLMResponse, VerdictOutput

_BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

_RESPONSE_SCHEMA: dict[str, Any] = {
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


class GeminiClient:
    """Async client around the Gemini generateContent REST API — implements LLMProvider."""

    def __init__(
        self,
        api_key: str,
        model: str = "gemini-2.5-flash",
        timeout: float = 120.0,
        inter_request_delay: float = 4.0,
        temperature: float | None = None,
    ) -> None:
        self.api_key = api_key
        self._model = model
        self.timeout = timeout
        self._inter_request_delay = inter_request_delay
        self._temperature = temperature
        self._url = _BASE_URL.format(model=model)

    @property
    def model_version(self) -> str:
        return self._model

    async def complete(
        self,
        prompt: str,
        output_schema: dict[str, Any],
        *,
        prompt_version: str = "unknown",
    ) -> LLMResponse:
        """Send prompt to Gemini and return a structured verdict response."""
        await asyncio.sleep(self._inter_request_delay)
        t0 = time.monotonic()
        output, attempts, first_attempt_valid = await self._call_with_retry(prompt)
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
        )

    async def _call_with_retry(self, prompt: str) -> tuple[VerdictOutput, int, bool]:
        last_error: Exception | None = None
        for attempt in range(1, 4):
            try:
                raw = await self._single_call(prompt)
                output = VerdictOutput.model_validate_json(raw)
                return output, attempt, (attempt == 1)
            except Exception as exc:  # noqa: BLE001
                last_error = exc
        raise RuntimeError(
            f"All 3 Gemini attempts failed. Last error: {last_error}"
        ) from last_error

    async def _single_call(self, prompt: str) -> str:
        generation_config: dict[str, Any] = {
            "responseMimeType": "application/json",
            "responseSchema": _RESPONSE_SCHEMA,
        }
        if self._temperature is not None:
            # Eval-only: pin the most deterministic decoding the API allows so the
            # cross-model comparison is sampling-noise-free. temperature=0 plus
            # topK=1 forces greedy/argmax selection; topP=1 is then moot. 0.0 is
            # intentional, hence the explicit `is not None` check. Gemini is never
            # wired into the product pipeline, so no production caller sets this.
            generation_config["temperature"] = self._temperature
            generation_config["topK"] = 1
            generation_config["topP"] = 1.0
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": generation_config,
        }
        # Send the key in a header, never as a URL query param: httpx (and most
        # proxies) log the full request URL at INFO, so a ?key=... param leaks the
        # credential into logs. The x-goog-api-key header is Google's documented
        # auth alternative and never appears in a loggable URL.
        headers = {"x-goog-api-key": self.api_key}
        async with create_http_client(self.timeout, "gemini") as client:
            response = await client.post(self._url, json=payload, headers=headers)
            response.raise_for_status()
            data = response.json()
            return data["candidates"][0]["content"]["parts"][0]["text"]
