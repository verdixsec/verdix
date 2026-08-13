# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Dillon Jayanthan
"""Tests for the Phase 4 web layer.

Uses FastAPI's TestClient (synchronous) with mocked stores and a pre-configured
app. All DB calls are patched so tests run without a real SQLite database.
"""
from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient

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
