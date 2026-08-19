# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Tests for the ingestion health group (ADR-019 Stage 2).

eve.json readability stays in Core Requirements, unchanged — only the live
pipeline-state item is new, in its own "ingestion" group, rendered in its
own section on the Setup screen (setup_health.html). The two are
deliberately separate items in separate groups, not merged; several tests
here exist specifically to prove they can disagree.

Exercises _check_ingestion() directly for most cases — network-backed checks
(Ollama, RDAP) live in _check_core()/_check_enrichment() and would make
these tests depend on external connectivity for no benefit here. One test
calls run_health_check() itself to cover the real call-site path end to end.
"""
from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

from src.ingestion.status import IngestionStatus
from src.web.health_check import (
    CheckItem,
    HealthResult,
    _check_core,
    _check_ingestion,
    run_health_check,
)

# ---------------------------------------------------------------------------
# _check_core / check_blocked_paths — eve.json: not-found vs. permission-denied
# (verification defect 2)
#
# On-box verification against real NFS found that os.access()/os.path.isfile()
# can disagree with what an actual read does: they answer against the
# container's local uid/gid view, while a server-side root_squash/uid-mapping
# denial only shows up when the read is actually attempted. So the fix (and
# these tests) drive the real operation — same idea as
# src/ingestion/test_tailer.py's _patch_stat_to_fail, adapted to open() rather
# than os.access, since os.access no longer participates in the result.
# ---------------------------------------------------------------------------


def _stub_ollama_ok():
    from src.web.health_check import CheckItem as _CI

    return patch(
        "src.web.health_check._check_ollama",
        new_callable=AsyncMock,
        return_value=_CI("AI Engine (Ollama)", "ok", "stubbed — not under test"),
    )


def _patch_open_to_fail(monkeypatch, target: Path, exc_type: type[OSError]):
    """Make open(target, ...) raise exc_type; open() for any other path is
    unaffected. Mirrors _patch_stat_to_fail's real-function-preserving shape."""
    import builtins

    real_open = builtins.open
    target_str = str(target)

    def _flaky_open(file, *args, **kwargs):
        if str(file) == target_str:
            raise exc_type("simulated failure")
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", _flaky_open)


async def test_eve_json_permission_denied_reports_permission_not_not_found(
    tmp_path: Path, monkeypatch
) -> None:
    eve = tmp_path / "eve.json"
    eve.write_text("")
    monkeypatch.setenv("VX_EVE_LOG_PATH", str(eve))
    _patch_open_to_fail(monkeypatch, eve, PermissionError)

    with _stub_ollama_ok():
        items = await _check_core()
    eve_item = next(i for i in items if i.label == "Alert log (eve.json)")
    assert eve_item.status == "error"
    assert "permission denied" in eve_item.detail.lower()
    assert "not found" not in eve_item.detail.lower()


async def test_eve_json_genuinely_absent_still_reports_not_found(monkeypatch) -> None:
    monkeypatch.setenv("VX_EVE_LOG_PATH", "/nonexistent/eve.json")

    with _stub_ollama_ok():
        items = await _check_core()
    eve_item = next(i for i in items if i.label == "Alert log (eve.json)")
    assert eve_item.status == "error"
    assert "not found" in eve_item.detail.lower()
    assert "permission denied" not in eve_item.detail.lower()


def test_check_blocked_paths_permission_denied_reports_permission_not_not_found(
    tmp_path: Path, monkeypatch
) -> None:
    """Same predicate, same bug, second call site (Retry re-probe)."""
    from src.web.health_check import check_blocked_paths

    eve = tmp_path / "eve.json"
    eve.write_text("")
    monkeypatch.setenv("VX_EVE_LOG_PATH", str(eve))
    monkeypatch.setenv("VX_SURICATA_CONFIG_PATH", "/nonexistent/suricata.yaml")
    _patch_open_to_fail(monkeypatch, eve, PermissionError)

    result = check_blocked_paths()
    assert result["eve_json"]["ok"] is False
    assert "permission denied" in result["eve_json"]["error"].lower()
    assert "does not exist" not in result["eve_json"]["error"].lower()


def test_check_blocked_paths_genuinely_absent_still_reports_not_found(
    monkeypatch,
) -> None:
    from src.web.health_check import check_blocked_paths

    monkeypatch.setenv("VX_EVE_LOG_PATH", "/nonexistent/eve.json")
    monkeypatch.setenv("VX_SURICATA_CONFIG_PATH", "/nonexistent/suricata.yaml")

    result = check_blocked_paths()
    assert result["eve_json"]["ok"] is False
    assert "does not exist" in result["eve_json"]["error"].lower()
    assert "permission denied" not in result["eve_json"]["error"].lower()


# ---------------------------------------------------------------------------
# _check_ingestion — pipeline state only
# ---------------------------------------------------------------------------


def test_ingestion_group_returns_exactly_one_item() -> None:
    """eve.json's check does not live here — it stayed in Core Requirements."""
    items = _check_ingestion(None)
    assert len(items) == 1
    assert items[0].label == "Ingestion pipeline"


def test_status_none_reports_unknown_not_a_crash() -> None:
    items = _check_ingestion(None)
    assert items[0].status == "info"


def test_pipeline_green_reports_ok() -> None:
    status = IngestionStatus()
    items = _check_ingestion(status)
    assert items[0].status == "ok"


def test_pipeline_red_reports_error_with_reason() -> None:
    status = IngestionStatus()
    for _ in range(5):
        status.record_failure(PermissionError("denied"))
    items = _check_ingestion(status)
    assert items[0].status == "error"
    assert "denied" in items[0].detail


def test_blocked_reports_error_with_blocked_reason() -> None:
    status = IngestionStatus()
    status.record_blocked("suricata.yaml unreadable")
    items = _check_ingestion(status)
    assert items[0].status == "error"
    assert "suricata.yaml unreadable" in items[0].detail


def test_ingestion_item_is_never_required() -> None:
    """A transient mid-run red must not gate all_required_ok — ADR-019 blocks
    only at startup, a later stage's concern, not on every retry blip."""
    status = IngestionStatus()
    for _ in range(5):
        status.record_failure(PermissionError("denied"))
    items = _check_ingestion(status)
    assert items[0].required is False


# ---------------------------------------------------------------------------
# all_required_ok — unchanged form; eve.json's required item lives in core
# exactly as it always did, so no aggregate change was needed for this revert
# ---------------------------------------------------------------------------


def test_all_required_ok_unaffected_by_ingestion_group() -> None:
    result = HealthResult()
    result.core = [CheckItem("Alert log (eve.json)", "error", "Not found", required=True)]
    result.ingestion = [CheckItem("Ingestion pipeline", "ok", "Green", required=False)]
    assert result.all_required_ok is False

    result.core = [CheckItem("Alert log (eve.json)", "ok", "Found", required=True)]
    result.ingestion = [CheckItem("Ingestion pipeline", "error", "Red", required=False)]
    assert result.all_required_ok is True  # red pipeline alone must not flip this


# ---------------------------------------------------------------------------
# run_health_check() — real call-site path, disagreement across two groups
# ---------------------------------------------------------------------------


async def test_run_health_check_file_readable_and_pipeline_red_disagree(
    tmp_path: Path, monkeypatch
) -> None:
    """The 2026-08-12 post-restoration state: the NFS group was fixed so the
    file reads again, but the pipeline task is still dead until a restart.
    core's eve.json item and the ingestion group's pipeline item must
    disagree here — that disagreement is the diagnosis."""
    eve = tmp_path / "eve.json"
    eve.write_text("")
    monkeypatch.setenv("VX_EVE_LOG_PATH", str(eve))

    status = IngestionStatus()
    for _ in range(5):
        status.record_failure(PermissionError("denied"))

    result = await run_health_check(status)

    eve_item = next(i for i in result.core if i.label == "Alert log (eve.json)")
    assert eve_item.status == "ok"
    assert eve_item.detail.startswith("Found at")

    assert len(result.ingestion) == 1
    pipeline_item = result.ingestion[0]
    assert pipeline_item.label == "Ingestion pipeline"
    assert pipeline_item.status == "error"


async def test_run_health_check_file_missing_and_pipeline_still_green_disagree(
    monkeypatch,
) -> None:
    """Symmetric case: the mount just went unreadable and the tailer hasn't
    polled again yet — core's eve.json item flips to error immediately while
    the ingestion group's pipeline item is still green until enough
    consecutive failures accumulate."""
    monkeypatch.setenv("VX_EVE_LOG_PATH", "/nonexistent/eve.json")
    status = IngestionStatus()

    result = await run_health_check(status)

    eve_item = next(i for i in result.core if i.label == "Alert log (eve.json)")
    assert eve_item.status == "error"

    pipeline_item = result.ingestion[0]
    assert pipeline_item.status == "ok"


# ---------------------------------------------------------------------------
# _check_ollama / _check_rdap route through the shared HTTP client factory
#
# No network calls here — create_http_client() is patched with a fake async
# context manager, so this only proves the call-site wiring (factory called,
# with the right timeout/purpose), not CA-bundle resolution itself. That's
# already covered exhaustively in src/infra/http/test_factory.py
# (SSL_CERT_FILE priority, VX_CA_BUNDLE_PATH fallback, proxy env vars); no
# need to re-test it here.
# ---------------------------------------------------------------------------


class _FakeResponse:
    def __init__(self, status_code: int = 200, json_data: dict | None = None) -> None:
        self.status_code = status_code
        self._json = json_data or {}

    def json(self) -> dict:
        return self._json


class _FakeAsyncClient:
    def __init__(self, response: _FakeResponse) -> None:
        self._response = response

    async def __aenter__(self) -> _FakeAsyncClient:
        return self

    async def __aexit__(self, *exc_info: object) -> bool:
        return False

    async def get(self, url: str) -> _FakeResponse:
        return self._response


async def test_check_ollama_routes_through_factory_with_matching_purpose() -> None:
    from src.web.health_check import _check_ollama

    response = _FakeResponse(200, {"models": [{"name": "gemma4:e4b-it-q8_0"}]})
    fake_client = _FakeAsyncClient(response)

    with patch(
        "src.infra.http.factory.create_http_client", return_value=fake_client
    ) as mock_factory:
        item = await _check_ollama()

    mock_factory.assert_called_once_with(10.0, "ollama")  # matches OllamaClient's own call
    assert item.status == "ok"


async def test_check_rdap_routes_through_factory_with_matching_purpose() -> None:
    from src.web.health_check import _check_rdap

    fake_client = _FakeAsyncClient(_FakeResponse(200))

    with patch(
        "src.infra.http.factory.create_http_client", return_value=fake_client
    ) as mock_factory:
        item = await _check_rdap()

    mock_factory.assert_called_once_with(8.0, "rdap")  # matches RDAPClient's own call
    assert item.status == "ok"


def test_health_check_source_has_no_direct_httpx_import() -> None:
    """Regression guard for the TID251 bypass. _check_ollama/_check_rdap
    import httpx locally inside the function body, so an isinstance/module
    check wouldn't catch a regression (a local import never touches the
    module's own namespace) — checked against the raw source instead, same
    technique as test_routes.py's feedback-modal source-content guard."""
    import src.web.health_check as hc_module

    source = Path(hc_module.__file__).read_text(encoding="utf-8")
    assert "import httpx" not in source


def test_to_dict_reports_app_version() -> None:
    """/api/health's version field is sourced from APP_VERSION, not a literal
    duplicated here — same single-source-of-truth requirement as the UI
    footer."""
    from src.telemetry.models import APP_VERSION

    result = HealthResult()
    assert result.to_dict()["version"] == APP_VERSION
