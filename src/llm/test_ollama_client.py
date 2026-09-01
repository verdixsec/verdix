# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Tests for OllamaClient — mocked HTTP via respx."""
from __future__ import annotations

import json

import httpx
import pytest
import respx
from httpx import Response
from structlog.testing import capture_logs

from src.llm.models import LLMResponse
from src.llm.ollama_client import OllamaClient, _build_corrective_prompt

_VALID_VERDICT = {
    "verdict_category": "likely_tp",
    "confidence_score": 0.92,
    "reasoning": "High-fidelity malware signature with confirmed malicious IP.",
    "contributing_facts": ["SID 2025553 is a FormBook CnC signature", "15/72 VT vendors flagged malicious"],
}

_OLLAMA_URL = "http://llm:11434/api/chat"


def _make_ollama_response(content: str, done_reason: str = "stop") -> dict:
    return {"message": {"role": "assistant", "content": content}, "done_reason": done_reason}


@pytest.fixture()
def client() -> OllamaClient:
    return OllamaClient(model="gemma4:e4b-it-q8_0", base_url=_OLLAMA_URL, timeout=10.0)


@pytest.fixture()
def valid_json_response() -> str:
    return json.dumps(_VALID_VERDICT)


class TestOllamaClientComplete:
    @pytest.mark.asyncio
    @respx.mock
    async def test_successful_verdict(self, client, valid_json_response):
        respx.post(_OLLAMA_URL).mock(
            return_value=Response(200, json=_make_ollama_response(valid_json_response))
        )
        response = await client.complete("test prompt", OllamaClient.OUTPUT_SCHEMA)
        assert isinstance(response, LLMResponse)
        assert response.verdict_category == "likely_tp"
        assert response.confidence_score == pytest.approx(0.92)
        assert response.first_attempt_valid is True
        assert response.attempts == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_model_version_in_response(self, client, valid_json_response):
        respx.post(_OLLAMA_URL).mock(
            return_value=Response(200, json=_make_ollama_response(valid_json_response))
        )
        response = await client.complete("test prompt", OllamaClient.OUTPUT_SCHEMA)
        assert response.model_version == "gemma4:e4b-it-q8_0"

    @pytest.mark.asyncio
    @respx.mock
    async def test_prompt_version_in_response(self, client, valid_json_response):
        respx.post(_OLLAMA_URL).mock(
            return_value=Response(200, json=_make_ollama_response(valid_json_response))
        )
        response = await client.complete(
            "test prompt", OllamaClient.OUTPUT_SCHEMA, prompt_version="verdict_v1"
        )
        assert response.prompt_version == "verdict_v1"

    @pytest.mark.asyncio
    @respx.mock
    async def test_latency_ms_positive(self, client, valid_json_response):
        respx.post(_OLLAMA_URL).mock(
            return_value=Response(200, json=_make_ollama_response(valid_json_response))
        )
        response = await client.complete("test prompt", OllamaClient.OUTPUT_SCHEMA)
        assert response.latency_ms >= 0

    @pytest.mark.asyncio
    @respx.mock
    async def test_sends_num_ctx_8192(self, client, valid_json_response):
        route = respx.post(_OLLAMA_URL).mock(
            return_value=Response(200, json=_make_ollama_response(valid_json_response))
        )
        await client.complete("test prompt", OllamaClient.OUTPUT_SCHEMA)
        sent_body = json.loads(route.calls[0].request.content)
        assert sent_body["options"]["num_ctx"] == 8192

    @pytest.mark.asyncio
    @respx.mock
    async def test_sends_temperature_zero_when_set(self, valid_json_response):
        """temperature=0.0 (the product pin) must reach the request options as 0."""
        client = OllamaClient(model="gemma4:e4b-it-q8_0", base_url=_OLLAMA_URL, timeout=10.0, temperature=0.0)
        route = respx.post(_OLLAMA_URL).mock(
            return_value=Response(200, json=_make_ollama_response(valid_json_response))
        )
        await client.complete("test prompt", OllamaClient.OUTPUT_SCHEMA)
        sent_body = json.loads(route.calls[0].request.content)
        assert sent_body["options"]["temperature"] == 0

    @pytest.mark.asyncio
    @respx.mock
    async def test_omits_temperature_when_unset(self, client, valid_json_response):
        """Default (no temperature) omits the key entirely — locks the default-omits-key contract."""
        route = respx.post(_OLLAMA_URL).mock(
            return_value=Response(200, json=_make_ollama_response(valid_json_response))
        )
        await client.complete("test prompt", OllamaClient.OUTPUT_SCHEMA)
        sent_body = json.loads(route.calls[0].request.content)
        assert "temperature" not in sent_body["options"]

    @pytest.mark.asyncio
    @respx.mock
    async def test_sends_num_thread_when_set(self, valid_json_response):
        """num_thread=16 (the ramon cgroup-mask pin) must reach the request options."""
        client = OllamaClient(
            model="gemma4:e4b-it-q8_0", base_url=_OLLAMA_URL, timeout=10.0, num_thread=16
        )
        route = respx.post(_OLLAMA_URL).mock(
            return_value=Response(200, json=_make_ollama_response(valid_json_response))
        )
        await client.complete("test prompt", OllamaClient.OUTPUT_SCHEMA)
        sent_body = json.loads(route.calls[0].request.content)
        assert sent_body["options"]["num_thread"] == 16

    @pytest.mark.asyncio
    @respx.mock
    async def test_omits_num_thread_when_unset(self, client, valid_json_response):
        """Default (no num_thread) omits the key entirely -- locks the default-omits-key
        contract, matching temperature's pattern."""
        route = respx.post(_OLLAMA_URL).mock(
            return_value=Response(200, json=_make_ollama_response(valid_json_response))
        )
        await client.complete("test prompt", OllamaClient.OUTPUT_SCHEMA)
        sent_body = json.loads(route.calls[0].request.content)
        assert "num_thread" not in sent_body["options"]

    @pytest.mark.asyncio
    @respx.mock
    async def test_sends_think_false(self, client, valid_json_response):
        """think:false cuts generation time ~79% on ramon with no category impact
        (docs/progress.md session 73, continued) — must always be sent, not gated
        on a flag."""
        route = respx.post(_OLLAMA_URL).mock(
            return_value=Response(200, json=_make_ollama_response(valid_json_response))
        )
        await client.complete("test prompt", OllamaClient.OUTPUT_SCHEMA)
        sent_body = json.loads(route.calls[0].request.content)
        assert sent_body["think"] is False

    @pytest.mark.asyncio
    @respx.mock
    async def test_sends_format_as_json_schema_object(self, client, valid_json_response):
        route = respx.post(_OLLAMA_URL).mock(
            return_value=Response(200, json=_make_ollama_response(valid_json_response))
        )
        await client.complete("test prompt", OllamaClient.OUTPUT_SCHEMA)
        sent_body = json.loads(route.calls[0].request.content)
        # format must be the schema as a JSON object, not the literal string "json" or a serialized string
        assert isinstance(sent_body["format"], dict)
        assert sent_body["format"]["type"] == "object"

    @pytest.mark.asyncio
    @respx.mock
    async def test_retry_on_invalid_json(self, client, valid_json_response):
        """First response is invalid JSON, second is valid — expects 2 attempts."""
        call_count = 0

        def side_effect(request):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return Response(200, json=_make_ollama_response("not valid json {{{"))
            return Response(200, json=_make_ollama_response(valid_json_response))

        respx.post(_OLLAMA_URL).mock(side_effect=side_effect)
        response = await client.complete("test prompt", OllamaClient.OUTPUT_SCHEMA)
        assert response.first_attempt_valid is False
        assert response.attempts == 2
        assert response.verdict_category == "likely_tp"

    @pytest.mark.asyncio
    @respx.mock
    async def test_raises_after_two_failures(self, client):
        """2 attempts total (down from 3) — both fail, raises RuntimeError."""
        route = respx.post(_OLLAMA_URL).mock(
            return_value=Response(200, json=_make_ollama_response("still not json"))
        )
        with pytest.raises(RuntimeError, match="All 2 Ollama attempts failed"):
            await client.complete("test prompt", OllamaClient.OUTPUT_SCHEMA)
        assert len(route.calls) == 2

    @pytest.mark.asyncio
    @respx.mock
    async def test_503_triggers_retry(self, client, valid_json_response):
        """503 (Ollama still starting) is transient -- retries once."""
        call_count = 0

        def side_effect(request):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return Response(503, text="Service Unavailable")
            return Response(200, json=_make_ollama_response(valid_json_response))

        respx.post(_OLLAMA_URL).mock(side_effect=side_effect)
        response = await client.complete("test prompt", OllamaClient.OUTPUT_SCHEMA)
        assert response.attempts == 2
        assert response.verdict_category == "likely_tp"

    @pytest.mark.asyncio
    @respx.mock
    async def test_500_does_not_retry(self, client):
        """500 is a real server-side defect, not a transient condition (session 70:
        22+ consecutive HTTP 500s from a memory-discovery bug where retrying never
        succeeded). Fails immediately, exactly one call made."""
        route = respx.post(_OLLAMA_URL).mock(
            return_value=Response(500, text="Internal Server Error")
        )
        with pytest.raises(httpx.HTTPStatusError):
            await client.complete("test prompt", OllamaClient.OUTPUT_SCHEMA)
        assert len(route.calls) == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_read_timeout_raises_immediately_without_retry(self, client):
        """The regression test for the actual bug: a read timeout must not retry
        with a 'your previous response was invalid JSON' corrective — there is no
        response to correct, and a second attempt costs another full timeout
        window for nothing."""
        route = respx.post(_OLLAMA_URL).mock(side_effect=httpx.ReadTimeout("timed out"))
        with pytest.raises(httpx.ReadTimeout):
            await client.complete("test prompt", OllamaClient.OUTPUT_SCHEMA)
        assert len(route.calls) == 1
        # The single request sent must be the original prompt, verbatim -- no
        # corrective text appended, since there was nothing to correct.
        sent_body = json.loads(route.calls[0].request.content)
        assert sent_body["messages"][0]["content"] == "test prompt"

    @pytest.mark.asyncio
    @respx.mock
    async def test_connect_error_retries_once(self, client, valid_json_response):
        """A connect error (e.g. the llm container restarting) is transient."""
        call_count = 0

        def side_effect(request):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise httpx.ConnectError("connection refused")
            return Response(200, json=_make_ollama_response(valid_json_response))

        respx.post(_OLLAMA_URL).mock(side_effect=side_effect)
        response = await client.complete("test prompt", OllamaClient.OUTPUT_SCHEMA)
        assert response.attempts == 2
        assert response.verdict_category == "likely_tp"

    @pytest.mark.asyncio
    @respx.mock
    async def test_done_reason_length_does_not_retry(self, client):
        """A done_reason=length response is truncated -- retrying at the same
        num_ctx will truncate the same way again."""
        route = respx.post(_OLLAMA_URL).mock(
            return_value=Response(
                200,
                json=_make_ollama_response(
                    '{"verdict_category": "likely_tp"', done_reason="length"
                ),
            )
        )
        with pytest.raises(RuntimeError, match="degenerate"):
            await client.complete("test prompt", OllamaClient.OUTPUT_SCHEMA)
        assert len(route.calls) == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_empty_content_does_not_retry(self, client):
        route = respx.post(_OLLAMA_URL).mock(
            return_value=Response(200, json=_make_ollama_response("   ", done_reason="stop"))
        )
        with pytest.raises(RuntimeError, match="degenerate"):
            await client.complete("test prompt", OllamaClient.OUTPUT_SCHEMA)
        assert len(route.calls) == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_retry_attempt_logs_json_invalid_failure_class(self, client, valid_json_response):
        """'Returned prose' -- content isn't JSON at all."""
        call_count = 0

        def side_effect(request):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return Response(200, json=_make_ollama_response("not valid json {{{"))
            return Response(200, json=_make_ollama_response(valid_json_response))

        respx.post(_OLLAMA_URL).mock(side_effect=side_effect)
        with capture_logs() as logs:
            await client.complete("test prompt", OllamaClient.OUTPUT_SCHEMA)
        retry_events = [e for e in logs if e["event"] == "llm_retry_attempt"]
        assert len(retry_events) == 1
        assert retry_events[0]["failure_class"] == "json_invalid"

    @pytest.mark.asyncio
    @respx.mock
    async def test_retry_attempt_logs_schema_invalid_failure_class(
        self, client, valid_json_response
    ):
        """'Returned valid JSON of the wrong shape' -- parses, fails the schema."""
        call_count = 0
        wrong_shape = json.dumps({"unexpected": "shape"})

        def side_effect(request):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return Response(200, json=_make_ollama_response(wrong_shape))
            return Response(200, json=_make_ollama_response(valid_json_response))

        respx.post(_OLLAMA_URL).mock(side_effect=side_effect)
        with capture_logs() as logs:
            await client.complete("test prompt", OllamaClient.OUTPUT_SCHEMA)
        retry_events = [e for e in logs if e["event"] == "llm_retry_attempt"]
        assert len(retry_events) == 1
        assert retry_events[0]["failure_class"] == "schema_invalid"

    @pytest.mark.asyncio
    @respx.mock
    async def test_contributing_facts_preserved(self, client, valid_json_response):
        respx.post(_OLLAMA_URL).mock(
            return_value=Response(200, json=_make_ollama_response(valid_json_response))
        )
        response = await client.complete("test prompt", OllamaClient.OUTPUT_SCHEMA)
        assert len(response.contributing_facts) == 2
        assert "FormBook" in response.contributing_facts[0]


class TestCorrectivePrompt:
    """Locks the corrective retry prompt's literal wording — a later edit that
    silently weakens it (e.g. dropping the schema restatement or the concision
    ask) should fail one of these."""

    def test_contains_literal_preamble_and_preview(self):
        prompt = _build_corrective_prompt("original prompt text", "not valid json {{{")
        assert prompt.startswith("original prompt text\n\n")
        assert (
            "Your previous response could not be parsed as valid JSON matching the "
            "required schema. It started with: not valid json {{{"
        ) in prompt

    def test_contains_literal_schema_restatement(self):
        prompt = _build_corrective_prompt("p", "bad")
        assert 'Return ONLY a single JSON object with exactly these fields:' in prompt
        assert (
            '- verdict_category: string, one of "likely_fp", "suspicious_investigate", "likely_tp"'
        ) in prompt
        assert "- confidence_score: number between 0.0 and 1.0" in prompt
        assert "- reasoning: a concise string (a few sentences, not a full essay)" in prompt
        assert "- contributing_facts: a concise array of short strings" in prompt
        assert "No preamble, no markdown fences, no text outside the JSON object." in prompt

    def test_preview_truncated_to_200_chars(self):
        long_failure = "x" * 500
        prompt = _build_corrective_prompt("p", long_failure)
        assert "x" * 200 in prompt
        assert "x" * 201 not in prompt


class TestOllamaClientOutputSchema:
    def test_output_schema_is_class_attribute(self):
        schema = OllamaClient.OUTPUT_SCHEMA
        assert schema["type"] == "object"
        assert "verdict_category" in schema["properties"]
        assert "confidence_score" in schema["properties"]
        assert "reasoning" in schema["properties"]
        assert "contributing_facts" in schema["properties"]

    def test_output_schema_requires_all_fields(self):
        required = OllamaClient.OUTPUT_SCHEMA["required"]
        assert set(required) == {"verdict_category", "confidence_score", "reasoning", "contributing_facts"}

    def test_verdict_category_enum_values(self):
        enum_values = OllamaClient.OUTPUT_SCHEMA["properties"]["verdict_category"]["enum"]
        assert "likely_fp" in enum_values
        assert "suspicious_investigate" in enum_values
        assert "likely_tp" in enum_values


class TestOllamaClientModelVersion:
    def test_model_version_property(self):
        client = OllamaClient(model="gemma4:e4b-it-q8_0")
        assert client.model_version == "gemma4:e4b-it-q8_0"

    def test_default_base_url(self):
        client = OllamaClient()
        assert "11434" in client.base_url
