# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Tests for the Phase 4 web layer.

Uses FastAPI's TestClient (synchronous) with mocked stores and a pre-configured
app. All DB calls are patched so tests run without a real SQLite database.
"""
from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient

_FIXTURES = Path(__file__).resolve().parent.parent / "infra" / "suricata_config" / "fixtures"
_REFERENCE_YAML = _FIXTURES / "reference.yaml"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_app(*, license_accepted: bool = True, admin_pw: str = "testpass"):
    """Create an app instance with controlled environment and mocked stores."""
    os.environ["VX_ADMIN_PASSWORD"] = admin_pw

    from src.web import auth as auth_mod
    from src.web import deps
    from src.web.app import create_app

    # Clear lockout state so tests are isolated from each other
    auth_mod._lockout.clear()

    # Inject in-memory license state
    deps._license_accepted = license_accepted

    # Provide minimal stub stores so route handlers don't crash on import
    event_store = MagicMock()
    event_store.query_alerts = AsyncMock(return_value=[])
    event_store.get_alert = AsyncMock(return_value=None)
    event_store.get_correlated_events = AsyncMock(return_value=[])
    event_store.count_analyzed_today = AsyncMock(return_value=0)
    event_store.count_alerts_by_status = AsyncMock(return_value={})

    op_store = MagicMock()
    op_store.get_config = AsyncMock(return_value="true" if license_accepted else None)
    op_store.set_config = AsyncMock()
    op_store.get_verdict = AsyncMock(return_value=None)
    op_store.get_current_verdict_for_alert = AsyncMock(return_value=None)
    op_store.link_disposition_to_alert = AsyncMock()

    disp_store = MagicMock()
    disp_store.get_latest_disposition = AsyncMock(return_value=None)
    disp_store.record_disposition = AsyncMock(return_value="disp-uuid")

    deps.configure_stores(event_store, op_store, disp_store)
    return create_app()


def _logged_in_client(app) -> TestClient:
    client = TestClient(app, raise_server_exceptions=False, follow_redirects=False)
    # Perform login
    resp = client.post("/login", data={"password": "testpass"})
    assert resp.status_code == 303, f"Login failed: {resp.status_code}"
    return client


# ---------------------------------------------------------------------------
# License gate tests
# ---------------------------------------------------------------------------

class TestLicenseGate:
    def test_unauthenticated_root_redirects_to_license_when_not_accepted(self):
        app = _make_app(license_accepted=False)
        client = TestClient(app, follow_redirects=False)
        resp = client.get("/queue")
        assert resp.status_code == 303
        assert resp.headers["location"] == "/setup/license"

    def test_setup_license_page_accessible_without_acceptance(self):
        app = _make_app(license_accepted=False)
        client = TestClient(app, follow_redirects=False)
        resp = client.get("/setup/license")
        assert resp.status_code == 200
        assert b"Community License" in resp.content

    def test_api_health_accessible_without_license(self):
        app = _make_app(license_accepted=False)
        client = TestClient(app, follow_redirects=False)
        with patch("src.web.routes.api_routes.run_health_check", new_callable=AsyncMock) as mock_hc:
            mock_hc.return_value = MagicMock(to_dict=lambda: {"core": [], "all_required_ok": True})
            resp = client.get("/api/health")
        assert resp.status_code == 200

    def test_liveness_probe_always_accessible(self):
        app = _make_app(license_accepted=False)
        client = TestClient(app, follow_redirects=False)
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_post_license_accept_sets_config_and_redirects(self):
        app = _make_app(license_accepted=False)
        from src.web import deps
        client = TestClient(app, follow_redirects=False)
        resp = client.post("/setup/license", data={"accepted": "true"})
        assert resp.status_code == 303
        assert resp.headers["location"] == "/setup/health"
        assert deps._license_accepted is True

    def test_post_license_decline_shows_warning(self):
        app = _make_app(license_accepted=False)
        client = TestClient(app, follow_redirects=False)
        resp = client.post("/setup/license", data={"accepted": "false"})
        assert resp.status_code == 200
        assert b"cannot be used" in resp.content.lower() or b"declined" in resp.content.lower()


# ---------------------------------------------------------------------------
# /health ingestion gate (ADR-019 Stage 2)
# ---------------------------------------------------------------------------

class TestHealthIngestionGate:
    def test_health_returns_200_when_green(self):
        from src.ingestion.status import IngestionStatus

        app = _make_app()
        app.state.ingestion_status = IngestionStatus()
        client = TestClient(app, follow_redirects=False)
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_health_returns_503_when_red(self):
        from src.ingestion.status import IngestionStatus

        app = _make_app()
        status = IngestionStatus()
        for _ in range(5):
            status.record_failure(PermissionError("denied"))
        app.state.ingestion_status = status
        client = TestClient(app, follow_redirects=False)
        resp = client.get("/health")
        assert resp.status_code == 503
        body = resp.json()
        assert body["status"] == "red"
        assert "denied" in body["reason"]

    def test_health_returns_503_when_blocked(self):
        from src.ingestion.status import IngestionStatus

        app = _make_app()
        status = IngestionStatus()
        status.record_blocked("suricata.yaml unreadable")
        app.state.ingestion_status = status
        client = TestClient(app, follow_redirects=False)
        resp = client.get("/health")
        assert resp.status_code == 503
        assert resp.json()["reason"] == "suricata.yaml unreadable"

    def test_health_missing_status_defaults_to_200(self):
        """create_app() alone (no main.py lifespan) never sets
        app.state.ingestion_status — must read as healthy, not crash."""
        app = _make_app()
        client = TestClient(app, follow_redirects=False)
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


# ---------------------------------------------------------------------------
# Ingestion blocked-state gate (ADR-019 Stage 3)
# ---------------------------------------------------------------------------

def _blocked_status():
    from src.ingestion.status import IngestionStatus
    status = IngestionStatus()
    status.record_blocked("eve.json unreadable at /host/suricata/logs/eve.json")
    return status


def _mid_run_red_status():
    from src.ingestion.status import IngestionStatus
    status = IngestionStatus()
    for _ in range(5):
        status.record_failure(PermissionError("denied"))
    return status


class TestIngestionBlockedGate:
    def test_blocked_redirects_dashboard_route(self):
        app = _make_app()
        app.state.ingestion_status = _blocked_status()
        client = _logged_in_client(app)
        resp = client.get("/queue")
        assert resp.status_code == 303
        assert resp.headers["location"] == "/setup/health"

    def test_blocked_setup_health_remains_reachable(self):
        app = _make_app()
        app.state.ingestion_status = _blocked_status()
        client = TestClient(app, follow_redirects=False)
        resp = client.get("/setup/health")
        assert resp.status_code == 200

    def test_blocked_health_remains_reachable(self):
        app = _make_app()
        app.state.ingestion_status = _blocked_status()
        client = TestClient(app, follow_redirects=False)
        resp = client.get("/health")
        # Correctly 503 (Stage 2: ingestion is red) but never redirected —
        # "reachable" here means the gate didn't intercept it.
        assert resp.status_code == 503
        assert "location" not in resp.headers

    def test_blocked_api_health_remains_reachable(self):
        app = _make_app()
        app.state.ingestion_status = _blocked_status()
        client = TestClient(app, follow_redirects=False)
        resp = client.get("/api/health")
        assert resp.status_code == 200

    def test_blocked_api_route_returns_503_json_not_redirect(self):
        """A JSON client can't act on an HTML redirect target — /api/* must
        get a 503 JSON body while blocked, not a 303 to /setup/health."""
        app = _make_app()
        status = _blocked_status()
        app.state.ingestion_status = status
        client = _logged_in_client(app)
        resp = client.get("/api/queue-depth")
        assert resp.status_code == 503
        assert "location" not in resp.headers
        assert resp.headers["content-type"].startswith("application/json")
        body = resp.json()
        assert body["status"] == "blocked"
        assert body["reason"] == status.blocked_reason
        assert "eve.json" in body["reason"]

    def test_blocked_static_assets_remain_reachable(self):
        app = _make_app()
        app.state.ingestion_status = _blocked_status()
        client = TestClient(app, follow_redirects=False)
        resp = client.get("/static/verdix-favicon.svg")
        assert resp.status_code == 200

    def test_blocked_login_remains_reachable(self):
        app = _make_app()
        app.state.ingestion_status = _blocked_status()
        client = TestClient(app, follow_redirects=False)
        resp = client.get("/login")
        assert resp.status_code == 200

    def test_blocked_no_redirect_loop_on_setup_health(self):
        """A gate that redirects /setup/health to itself would infinite-loop —
        a broken exemption here is worse than no gate at all."""
        app = _make_app()
        app.state.ingestion_status = _blocked_status()
        client = TestClient(app, follow_redirects=True)
        resp = client.get("/setup/health")
        assert resp.status_code == 200
        assert len(resp.history) == 0  # zero redirects followed to get here

    def test_mid_run_red_does_not_redirect_dashboard(self):
        """Mid-run red (retries in progress, blocked_reason unset) must not
        gate the dashboard — there may be verdicts worth reading and an
        analyst mid-investigation. Only the startup-blocked state gates."""
        app = _make_app()
        app.state.ingestion_status = _mid_run_red_status()
        client = _logged_in_client(app)
        resp = client.get("/queue")
        assert resp.status_code == 200


class TestReCheckAction:
    """The Retry button on /setup/health targets this same GET route, so
    every load re-probes — there is no separate Re-check endpoint."""

    def test_recheck_still_failing_reports_error_and_keeps_gate(self, tmp_path, monkeypatch):
        monkeypatch.setenv("VX_EVE_LOG_PATH", str(tmp_path / "missing-eve.json"))
        monkeypatch.setenv("VX_SURICATA_CONFIG_PATH", str(tmp_path / "missing-suricata.yaml"))

        app = _make_app()
        status = _blocked_status()
        app.state.ingestion_status = status
        client = TestClient(app, follow_redirects=False)

        resp = client.get("/setup/health")
        assert resp.status_code == 200
        body = resp.text
        assert "Startup Blocked" in body
        assert "docker compose restart app" not in body
        assert "eve.json" in body
        assert "suricata.yaml" in body

        assert status.blocked_reason is not None  # gate unchanged

        dash = client.get("/queue")
        assert dash.status_code == 303
        assert dash.headers["location"] == "/setup/health"

    def test_recheck_fixed_paths_reports_success_keeps_gate_and_shows_restart(
        self, tmp_path, monkeypatch
    ):
        eve = tmp_path / "eve.json"
        eve.write_text("")
        monkeypatch.setenv("VX_EVE_LOG_PATH", str(eve))
        monkeypatch.setenv("VX_SURICATA_CONFIG_PATH", str(_REFERENCE_YAML))

        app = _make_app()
        status = _blocked_status()
        app.state.ingestion_status = status
        client = TestClient(app, follow_redirects=False)

        resp = client.get("/setup/health")
        assert resp.status_code == 200
        body = resp.text
        assert "Startup Blocked" in body
        assert "Paths are readable now" in body
        assert "docker compose restart app" in body

        assert status.blocked_reason is not None  # gate NOT lifted

        dash = client.get("/queue")
        assert dash.status_code == 303
        assert dash.headers["location"] == "/setup/health"


class TestBlockedDashboardGate:
    """Verification defect 3: on-box testing found 'Go to Dashboard' rendered
    enabled and blue directly beneath a red STARTUP BLOCKED banner whenever
    health.all_required_ok happened to be true — e.g. right after a Retry
    fixed both blocking paths, since the other Core Requirements items
    (admin password, Ollama) are unrelated to the block and can independently
    be green. Clicking it did still redirect back to /setup/health (the
    middleware gate never had a hole), but a live-looking blue button that
    silently bounces the operator back reads as broken. The button and
    footer must key off `blocked`, not `health.all_required_ok` alone.
    """

    @staticmethod
    def _fake_all_required_ok_result():
        result = MagicMock()
        result.to_dict.return_value = {
            "core": [], "resources": [], "network": [], "enrichment": [], "ingestion": [],
            "all_required_ok": True,
        }
        return result

    @staticmethod
    def _dashboard_anchor(body: str) -> str:
        start = body.index('href="/login" class="btn btn-primary"')
        return body[start: body.index(">", start)]

    def test_blocked_with_all_required_ok_disables_dashboard_button(self):
        app = _make_app()
        app.state.ingestion_status = _blocked_status()
        client = TestClient(app, follow_redirects=False)

        with patch(
            "src.web.routes.setup.run_health_check",
            new_callable=AsyncMock,
            return_value=self._fake_all_required_ok_result(),
        ), patch(
            "src.web.routes.setup.check_blocked_paths",
            return_value={
                "suricata_yaml": {"path": "x", "ok": False, "error": "still broken"},
                "eve_json": {"path": "y", "ok": True, "error": None},
                "all_ok": False,
            },
        ):
            resp = client.get("/setup/health")

        assert resp.status_code == 200
        body = resp.text
        assert "pointer-events:none" in self._dashboard_anchor(body)
        assert "All required checks passed." not in body

    def test_blocked_paths_now_fixed_still_disables_dashboard_button(self):
        """The 'Paths are readable now, restart' branch must also keep the
        button disabled — a restart is still required, and a live-looking
        button that silently bounces back is the actual defect."""
        app = _make_app()
        app.state.ingestion_status = _blocked_status()
        client = TestClient(app, follow_redirects=False)

        with patch(
            "src.web.routes.setup.run_health_check",
            new_callable=AsyncMock,
            return_value=self._fake_all_required_ok_result(),
        ), patch(
            "src.web.routes.setup.check_blocked_paths",
            return_value={
                "suricata_yaml": {"path": "x", "ok": True, "error": None},
                "eve_json": {"path": "y", "ok": True, "error": None},
                "all_ok": True,
            },
        ):
            resp = client.get("/setup/health")

        body = resp.text
        assert "Paths are readable now" in body
        assert "pointer-events:none" in self._dashboard_anchor(body)

    def test_not_blocked_all_required_ok_enables_dashboard_button(self):
        """Companion: outside the blocked state, the original all_required_ok
        -only gating is unchanged."""
        app = _make_app()
        client = TestClient(app, follow_redirects=False)  # no ingestion_status set -> not blocked

        with patch(
            "src.web.routes.setup.run_health_check",
            new_callable=AsyncMock,
            return_value=self._fake_all_required_ok_result(),
        ):
            resp = client.get("/setup/health")

        body = resp.text
        assert "All required checks passed." in body
        assert "pointer-events:none" not in self._dashboard_anchor(body)


# ---------------------------------------------------------------------------
# Auth tests
# ---------------------------------------------------------------------------

class TestAuth:
    def test_queue_requires_auth(self):
        app = _make_app()
        client = TestClient(app, follow_redirects=False)
        resp = client.get("/queue")
        assert resp.status_code == 303
        assert resp.headers["location"] == "/login"

    def test_correct_password_sets_session_and_redirects(self):
        app = _make_app()
        client = TestClient(app, follow_redirects=False)
        resp = client.post("/login", data={"password": "testpass"})
        assert resp.status_code == 303
        assert resp.headers["location"] == "/queue"

    def test_wrong_password_returns_401(self):
        app = _make_app()
        client = TestClient(app, follow_redirects=False)
        resp = client.post("/login", data={"password": "wrongpass"})
        assert resp.status_code == 401
        assert b"Incorrect" in resp.content

    def test_wrong_password_increments_lockout(self):
        from src.web import auth as auth_mod
        auth_mod._lockout.clear()
        app = _make_app()
        client = TestClient(app, follow_redirects=False)
        for _ in range(5):
            client.post("/login", data={"password": "bad"})
        resp = client.post("/login", data={"password": "bad"})
        assert resp.status_code == 429

    def test_logout_clears_session(self):
        app = _make_app()
        client = _logged_in_client(app)
        resp = client.post("/logout")
        assert resp.status_code == 303
        # Now queue should redirect to login
        resp2 = client.get("/queue")
        assert resp2.status_code == 303
        assert resp2.headers["location"] == "/login"

    def test_login_page_accessible_after_license(self):
        app = _make_app()
        client = TestClient(app, follow_redirects=False)
        resp = client.get("/login")
        assert resp.status_code == 200
        assert b"Sign In" in resp.content

    def test_authenticated_redirected_away_from_login(self):
        app = _make_app()
        client = _logged_in_client(app)
        resp = client.get("/login")
        assert resp.status_code == 303
        assert resp.headers["location"] == "/queue"


# ---------------------------------------------------------------------------
# Queue route tests
# ---------------------------------------------------------------------------

class TestQueueRoute:
    def test_queue_renders_when_authenticated(self):
        app = _make_app()
        client = _logged_in_client(app)
        resp = client.get("/queue")
        assert resp.status_code == 200
        assert b"Alert Queue" in resp.content or b"Verdix" in resp.content

    def test_queue_window_param_accepted(self):
        app = _make_app()
        client = _logged_in_client(app)
        for w in ("24h", "7d", "30d"):
            resp = client.get(f"/queue?window={w}")
            assert resp.status_code == 200

    def test_queue_invalid_window_defaults_to_24h(self):
        app = _make_app()
        client = _logged_in_client(app)
        resp = client.get("/queue?window=invalid")
        assert resp.status_code == 200

    @staticmethod
    def _queue_panel_html(body: str) -> str:
        """Isolate the server-rendered #queuePanel div's own markup.

        The client-side script (queue.html) embeds both the 'Queue clear'
        and 'No new alerts — ingestion stopped' strings unconditionally as
        JS source, since the poll must be able to render either state later
        — so a whole-page substring check can't tell initial server-render
        state from the JS's own literal text. Scoped to the panel div,
        which Jinja renders with exactly one branch.
        """
        start = body.index('id="queuePanel"')
        end = body.index("</div>", start)
        return body[start:end]

    def test_queue_page_render_red_ingestion_shows_red_before_any_poll(self):
        """A page loaded while ingestion is already red must be correct on
        first paint, not just after the 15s poll (ADR-019 Stage 4) — the
        gap this test guards against is the ADR's own failure mode: an
        empty queue and 'Queue clear' with a dead pipeline underneath."""
        from src.ingestion.status import IngestionStatus

        app = _make_app()
        status = IngestionStatus()
        for _ in range(5):
            status.record_failure(PermissionError("denied"))
        app.state.ingestion_status = status
        client = _logged_in_client(app)

        resp = client.get("/queue")
        assert resp.status_code == 200
        body = resp.text
        panel = self._queue_panel_html(body)
        assert "Queue clear" not in panel
        assert "No new alerts" in panel
        assert "Ingestion stopped" in body
        assert 'class="queue-dot red" id="ingestionDot"' in body
        assert "denied" in body  # reason surfaced in the indicator's title

    def test_queue_page_render_green_ingestion_shows_queue_clear(self):
        """Companion to the red case above: proves the added elif branch
        didn't change the default (green, empty queue) rendering."""
        from src.ingestion.status import IngestionStatus

        app = _make_app()
        app.state.ingestion_status = IngestionStatus()
        client = _logged_in_client(app)

        resp = client.get("/queue")
        assert resp.status_code == 200
        body = resp.text
        panel = self._queue_panel_html(body)
        assert "Queue clear" in panel
        assert "No new alerts" not in panel
        assert 'class="queue-dot" id="ingestionDot"' in body

    def test_ingestion_indicator_green_label_is_ingestion_live(self):
        """Verification defect 4: a bare 'Ingestion' label next to 'Queue
        clear' left the reader inferring that green means good — two
        similar-looking green items meaning entirely different things (a
        subsystem state vs. a workload count). The red case was already a
        complete statement ('Ingestion stopped'); the green case needed one
        too, matching the LIVE badge the health screen already uses for the
        same thing."""
        from src.ingestion.status import IngestionStatus

        app = _make_app()
        app.state.ingestion_status = IngestionStatus()
        client = _logged_in_client(app)

        resp = client.get("/queue")
        body = resp.text
        assert '<span id="ingestionLabel">Ingestion live</span>' in body
        assert "textContent = 'Ingestion live'" in body  # JS-side poll update, same wording

    def test_queue_table_partial_never_includes_feedback_modal(self):
        """Regression guard: the 15s background refresh (queue.html) replaces
        #tableWrap's innerHTML wholesale. If the feedback modal — or any
        future in-page form — ends up inside _queue_table.html instead of
        staying a sibling of #tableWrap, it gets torn down on every refresh,
        reintroducing the bug fixed in fix/queue-page-reload (a full-page
        reload used to wipe an open modal mid-typing). Checked against the
        raw template source so it fails even if nothing ever renders it.
        """
        path = os.path.join(
            os.path.dirname(__file__), "templates", "_queue_table.html"
        )
        with open(path, encoding="utf-8") as f:
            source = f.read()
        assert "_feedback_modal.html" not in source
        assert "feedbackModal" not in source


class TestQueueRowsApi:
    def test_queue_rows_requires_auth(self):
        app = _make_app()
        client = TestClient(app, follow_redirects=False)
        resp = client.get("/api/queue-rows")
        assert resp.status_code == 401

    def test_queue_rows_returns_html_fragment_with_total_header(self):
        app = _make_app()
        from src.web import deps
        deps._event_store.query_alerts = AsyncMock(return_value=[])

        client = _logged_in_client(app)
        resp = client.get("/api/queue-rows")
        assert resp.status_code == 200
        assert "X-Queue-Total" in resp.headers
        assert resp.headers["X-Queue-Total"] == "0"
        # The fragment must not carry the feedback modal along with it —
        # same invariant as the source-file check above, verified end to
        # end through the actual route this time.
        assert "_feedback_modal.html" not in resp.text
        assert "feedbackModal" not in resp.text

    def test_queue_rows_window_param_accepted(self):
        app = _make_app()
        client = _logged_in_client(app)
        for w in ("24h", "7d", "30d"):
            resp = client.get(f"/api/queue-rows?window={w}")
            assert resp.status_code == 200


# ---------------------------------------------------------------------------
# /api/queue-depth ingestion field (ADR-019 Stage 4)
# ---------------------------------------------------------------------------

class TestQueueDepthIngestionField:
    def test_queue_depth_ingestion_green(self):
        from src.ingestion.status import IngestionStatus

        app = _make_app()
        app.state.ingestion_status = IngestionStatus()
        client = _logged_in_client(app)
        resp = client.get("/api/queue-depth")
        assert resp.status_code == 200
        assert resp.json()["ingestion"] == {"state": "green"}

    def test_queue_depth_ingestion_red_carries_short_reason(self):
        from src.ingestion.status import IngestionStatus

        app = _make_app()
        status = IngestionStatus()
        for _ in range(5):
            status.record_failure(PermissionError("denied"))
        app.state.ingestion_status = status
        client = _logged_in_client(app)
        resp = client.get("/api/queue-depth")
        assert resp.status_code == 200
        ingestion = resp.json()["ingestion"]
        assert ingestion["state"] == "red"
        assert "denied" in ingestion["reason"]

    def test_queue_depth_missing_status_defaults_to_green(self):
        """create_app() alone (no main.py lifespan) never sets
        app.state.ingestion_status — must read as healthy, matching /health's
        existing default-to-ok convention."""
        app = _make_app()
        client = _logged_in_client(app)
        resp = client.get("/api/queue-depth")
        assert resp.status_code == 200
        assert resp.json()["ingestion"] == {"state": "green"}


class TestQueueIngestionIndicatorSource:
    """queue.html's ingestion indicator and zero-queue suppression logic run
    client-side; nothing in this Python suite executes JS. These checks
    confirm the wiring is present and correctly ordered in the rendered
    output — same technique as test_queue_table_partial_never_includes_
    feedback_modal above. The actual client-side behavior across all four
    states (green, red, red-with-backlog, blocked-503) was verified with a
    throwaway Node harness against this exact extracted script during
    development; that harness isn't part of this suite since the repo has no
    other JS-execution test dependency to hang it on.
    """

    def _rendered_queue_html(self) -> str:
        app = _make_app()
        client = _logged_in_client(app)
        resp = client.get("/queue")
        assert resp.status_code == 200
        return resp.text

    def test_indicator_element_present_for_both_states(self):
        html = self._rendered_queue_html()
        assert 'id="ingestionIndicator"' in html
        assert 'id="ingestionDot"' in html
        assert 'id="ingestionLabel"' in html
        assert "_updateIngestionIndicator" in html
        assert "ingestion.state === 'red'" in html

    def test_zero_queue_red_branch_precedes_queue_clear_branch(self):
        """The ingestion-red zero-queue branch must be checked before the
        unconditional 'Queue clear' branch, or the red case would never be
        reached — an if/elif ordering bug would silently restore the exact
        2026-08-12 failure mode."""
        html = self._rendered_queue_html()
        red_branch_idx = html.index("ingestion stopped'")
        queue_clear_idx = html.index("Queue clear'")
        assert red_branch_idx < queue_clear_idx

    def test_queue_depth_fetch_checks_response_ok_before_parsing(self):
        """A blocked (503) or unauthenticated (401) /api/queue-depth response
        must not fall through to the zero-queue branch — Stage 3 made /api/*
        return 503 JSON on block, and fetch() does not reject on a non-2xx
        status, so an unguarded .then(r => r.json()) would silently render
        'Queue clear' from a body with no queue-depth fields at all."""
        html = self._rendered_queue_html()
        assert "if (!r.ok) return null;" in html


# ---------------------------------------------------------------------------
# Alert route tests
# ---------------------------------------------------------------------------

class TestAlertRoute:
    def test_alert_404_for_unknown_id(self):
        app = _make_app()
        client = _logged_in_client(app)
        resp = client.get("/alert/no-such-id")
        assert resp.status_code == 404

    def test_disposition_accept_redirects_to_queue(self):
        app = _make_app()
        from src.web import deps
        alert_id = "test-alert-123"

        # Patch get_alert in event_store to return a real alert
        deps._event_store.get_alert = AsyncMock(return_value={
            "alert_id": alert_id, "signature_msg": "Test sig",
            "signature_severity": 1, "src_ip": "1.2.3.4",
            "dst_ip": "5.6.7.8", "src_port": 1234, "dst_port": 80,
            "proto": "TCP", "app_proto": "http", "event_timestamp": "2026-01-01T00:00:00Z",
            "status": "analyzed", "verdict_id": None, "disposition_id": None,
            "flow_id": None, "home_net_match": None,
            "attacker_role": None, "victim_role": None,
            "role_assignment_confidence": None, "role_assignment_reasoning": None,
            "role_assignment_signals": None,
        })

        client = _logged_in_client(app)
        resp = client.post(
            f"/alert/{alert_id}/disposition",
            data={"action": "accept", "override_reason": ""},
        )
        assert resp.status_code == 303
        assert resp.headers["location"] == "/queue"

    def test_disposition_invalid_action_returns_400(self):
        app = _make_app()
        client = _logged_in_client(app)
        resp = client.post(
            "/alert/some-id/disposition",
            data={"action": "invalid_action", "override_reason": ""},
        )
        assert resp.status_code == 400

    def test_disposition_requires_auth(self):
        app = _make_app()
        client = TestClient(app, follow_redirects=False)
        resp = client.post(
            "/alert/some-id/disposition",
            data={"action": "accept", "override_reason": ""},
        )
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# API routes tests
# ---------------------------------------------------------------------------

class TestApiRoutes:
    def test_queue_depth_returns_json(self):
        app = _make_app()
        from src.web import deps
        deps._event_store.count_analyzed_today = AsyncMock(return_value=5)
        deps._event_store.query_alerts = AsyncMock(return_value=[])

        client = _logged_in_client(app)
        resp = client.get("/api/queue-depth")
        assert resp.status_code == 200
        data = resp.json()
        assert "queued" in data
        assert "daily_cap" in data

    def test_queue_depth_requires_auth(self):
        app = _make_app()
        client = TestClient(app, follow_redirects=False)
        resp = client.get("/api/queue-depth")
        assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Feedback / deletion-request tests
# ---------------------------------------------------------------------------

class TestFeedbackApi:
    def test_feedback_requires_auth(self):
        app = _make_app()
        client = TestClient(app, follow_redirects=False)
        resp = client.post("/api/feedback", json={"feedback_text": "hi"})
        assert resp.status_code == 401

    def test_feedback_empty_text_returns_422_and_does_not_forward(self):
        app = _make_app()
        client = _logged_in_client(app)
        with patch(
            "src.web.routes.api_routes.telemetry_client.submit",
            new_callable=AsyncMock,
        ) as mock_submit:
            resp = client.post("/api/feedback", json={"feedback_text": "   "})
        assert resp.status_code == 422
        mock_submit.assert_not_called()

    def test_invalid_submission_type_returns_422_and_does_not_forward(self):
        app = _make_app()
        client = _logged_in_client(app)
        with patch(
            "src.web.routes.api_routes.telemetry_client.submit",
            new_callable=AsyncMock,
        ) as mock_submit:
            resp = client.post(
                "/api/feedback",
                json={"submission_type": "telemetry", "feedback_text": "hi"},
            )
        assert resp.status_code == 422
        mock_submit.assert_not_called()

    def test_feedback_accepted_and_forwarded_with_stamped_fields(self):
        app = _make_app()
        client = _logged_in_client(app)
        with patch(
            "src.web.routes.api_routes.telemetry_client.submit",
            new_callable=AsyncMock,
        ) as mock_submit:
            resp = client.post("/api/feedback", json={"feedback_text": "great tool"})
        assert resp.status_code == 200
        assert resp.json()["ok"] is True
        mock_submit.assert_called_once()
        payload = mock_submit.call_args.args[0]
        assert payload["submission_type"] == "feedback"
        assert payload["feedback_text"] == "great tool"
        assert payload["install_id"]  # stamped server-side, never sent by browser
        assert payload["submitted_at"]

    def test_deletion_request_allows_prefilled_text_and_stamps_install_id(self):
        app = _make_app()
        from src.web import deps
        deps._operational_store.get_config = AsyncMock(return_value="install-abc")
        client = _logged_in_client(app)
        with patch(
            "src.web.routes.api_routes.telemetry_client.submit",
            new_callable=AsyncMock,
        ) as mock_submit:
            resp = client.post(
                "/api/feedback",
                json={
                    "submission_type": "deletion_request",
                    "feedback_text": "Data deletion requested for this installation.",
                },
            )
        assert resp.status_code == 200
        mock_submit.assert_called_once()
        payload = mock_submit.call_args.args[0]
        assert payload["submission_type"] == "deletion_request"
        assert payload["install_id"] == "install-abc"
        assert payload["submitted_at"]
