# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Tests for OllamaClient — mocked HTTP via respx."""
from __future__ import annotations

import json

import pytest
import respx
from httpx import Response

from src.llm.models import LLMResponse
from src.llm.ollama_client import OllamaClient

_VALID_VERDICT = {
    "verdict_category": "likely_tp",
    "confidence_score": 0.92,
    "reasoning": "High-fidelity malware signature with confirmed malicious IP.",
    "contributing_facts": ["SID 2025553 is a FormBook CnC signature", "15/72 VT vendors flagged malicious"],
}

_OLLAMA_URL = "http://llm:11434/api/chat"


def _make_ollama_response(content: str) -> dict:
    return {"message": {"role": "assistant", "content": content}}


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
    async def test_raises_after_three_failures(self, client):
        respx.post(_OLLAMA_URL).mock(
            return_value=Response(200, json=_make_ollama_response("still not json"))
        )
        with pytest.raises(RuntimeError, match="All 3 Ollama attempts failed"):
            await client.complete("test prompt", OllamaClient.OUTPUT_SCHEMA)

    @pytest.mark.asyncio
    @respx.mock
    async def test_http_error_triggers_retry(self, client, valid_json_response):
        call_count = 0

        def side_effect(request):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return Response(500, text="Internal Server Error")
            return Response(200, json=_make_ollama_response(valid_json_response))

        respx.post(_OLLAMA_URL).mock(side_effect=side_effect)
        response = await client.complete("test prompt", OllamaClient.OUTPUT_SCHEMA)
        assert response.attempts == 2

    @pytest.mark.asyncio
    @respx.mock
    async def test_contributing_facts_preserved(self, client, valid_json_response):
        respx.post(_OLLAMA_URL).mock(
            return_value=Response(200, json=_make_ollama_response(valid_json_response))
        )
        response = await client.complete("test prompt", OllamaClient.OUTPUT_SCHEMA)
        assert len(response.contributing_facts) == 2
        assert "FormBook" in response.contributing_facts[0]


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
