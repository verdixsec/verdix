# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""LLMProvider interface — abstract over LLM verdict generation.

Concrete implementations:
  v0.1  src/llm/ollama_client.py  — Ollama (local sibling container)
  v1+   BYO-endpoint (any OpenAI-compatible HTTP API)
        Hosted opt-in (Anthropic, OpenAI, Azure — with explicit data-flow ack)

Application code must import this Protocol, never a concrete class.
Concrete instances arrive via dependency injection.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

if TYPE_CHECKING:
    from src.llm.models import LLMResponse


@runtime_checkable
class LLMProvider(Protocol):
    """Generate an AI verdict for a single Suricata alert."""

    @property
    def model_version(self) -> str:
        """Identifier string for the model being used (e.g. 'gemma4:e4b-it-q8_0').

        Persisted in every verdict row for provenance and regression testing.
        """
        ...

    async def complete(
        self,
        prompt: str,
        output_schema: dict[str, Any],
        *,
        prompt_version: str = "unknown",
    ) -> "LLMResponse":
        """Send prompt to the LLM and return a structured verdict response.

        Args:
            prompt:         Fully assembled verdict prompt (from PromptBuilder).
            output_schema:  JSON schema dict the LLM must conform to.
            prompt_version: Template version tag persisted in the verdict row.

        Returns:
            LLMResponse with verdict_category, confidence, reasoning, and raw I/O.

        Never raises for recoverable failures (timeout, malformed JSON after retries).
        Raises AppError subclass only for programmer errors (misconfigured endpoint).
        """
        ...
