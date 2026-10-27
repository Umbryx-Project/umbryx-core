"""Extended webhooks tests — HMAC, event handling."""
import hashlib
import hmac
import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    r = module_client.post("/api/projects", json={"name": "WHExtTest", "added": "2025-01-01T00:00:00Z", "status": "active"})
    if r.status_code == 201:
        _state["pid"] = r.json()["id"]
    yield


class TestWebhookTokenManagement:
    def test_get_webhook(self, module_client: TestClient):
        if not _state.get("pid"):
            pytest.skip("No project")
        r = module_client.get(f"/api/projects/{_state['pid']}/webhook")
        assert r.status_code == 200
        data = r.json()
        _state["token"] = data.get("token", "")

    def test_regenerate_webhook(self, module_client: TestClient):
        if not _state.get("pid"):
            pytest.skip("No project")
        # regenerate_webhook_token() fail-closes without WEBHOOK_HMAC_SECRET
        # (security audit finding F11); patch just for this call so the
        # ingestion tests below still exercise the no-HMAC-configured path.
        with patch("app.routers.webhooks.WEBHOOK_HMAC_SECRET", "test-hmac-secret"):
            r = module_client.post(f"/api/projects/{_state['pid']}/webhook/regenerate")
        assert r.status_code == 200
        data = r.json()
        assert "token" in data
        _state["token"] = data["token"]

    def test_webhook_404_project(self, module_client: TestClient):
        r = module_client.get("/api/projects/nonexistent/webhook")
        assert r.status_code == 404


HMAC_SECRET = "test-hmac-secret"


def _signed_post(client: TestClient, url: str, payload: dict):
    """POST with a valid X-Hub-Signature-256 for HMAC_SECRET.

    _verify_hmac now fails closed when WEBHOOK_HMAC_SECRET isn't
    configured (security audit finding F11) — every ingestion test needs
    both the secret patched in and a correctly signed request body.
    """
    body = json.dumps(payload).encode()
    sig = "sha256=" + hmac.new(HMAC_SECRET.encode(), body, hashlib.sha256).hexdigest()
    with patch("app.routers.webhooks.WEBHOOK_HMAC_SECRET", HMAC_SECRET):
        return client.post(
            url, content=body, headers={"Content-Type": "application/json", "X-Hub-Signature-256": sig}
        )


class TestWebhookReceive:
    def test_receive_beacon_event(self, module_client: TestClient):
        if not _state.get("pid"):
            pytest.skip("No project created")
        if not _state.get("token"):
            pytest.skip("No webhook token")
        r = _signed_post(
            module_client,
            f"/api/webhooks/{_state['token']}",
            {
                "type": "beacon",
                "ip": "10.0.0.50",
                "hostname": "webhook-host",
                "os": "Linux",
                "source": "test",
            },
        )
        assert r.status_code in (200, 500)

    def test_receive_cred_event(self, module_client: TestClient):
        if not _state.get("token"):
            pytest.skip("No webhook token")
        r = _signed_post(
            module_client,
            f"/api/webhooks/{_state['token']}",
            {
                "type": "cred",
                "username": "webhook_user",
                "secret": "webhook_pass",
                "ip": "10.0.0.50",
            },
        )
        assert r.status_code == 200

    def test_receive_finding_event(self, module_client: TestClient):
        if not _state.get("token"):
            pytest.skip("No webhook token")
        r = _signed_post(
            module_client,
            f"/api/webhooks/{_state['token']}",
            {
                "type": "finding",
                "title": "Webhook Finding",
                "severity": "high",
                "description": "Test finding from webhook",
                "ip": "10.0.0.50",
            },
        )
        assert r.status_code == 200

    def test_invalid_token(self, module_client: TestClient):
        r = _signed_post(
            module_client,
            "/api/webhooks/invalid_token",
            {"type": "beacon", "ip": "10.0.0.1"},
        )
        assert r.status_code == 404

    def test_no_signature_rejected(self, module_client: TestClient):
        if not _state.get("token"):
            pytest.skip("No webhook token")
        with patch("app.routers.webhooks.WEBHOOK_HMAC_SECRET", HMAC_SECRET):
            r = module_client.post(
                f"/api/webhooks/{_state['token']}", json={"type": "beacon", "ip": "10.0.0.1"}
            )
        assert r.status_code == 403

    def test_no_secret_configured_rejects(self, module_client: TestClient):
        # WEBHOOK_HMAC_SECRET unset (test default): must reject outright,
        # not treat "no secret" as "verification not required" (F11).
        if not _state.get("token"):
            pytest.skip("No webhook token")
        r = module_client.post(
            f"/api/webhooks/{_state['token']}", json={"type": "beacon", "ip": "10.0.0.1"}
        )
        assert r.status_code == 403


class TestWebhookCheck:
    def test_check_valid_token(self, module_client: TestClient):
        if not _state.get("token"):
            pytest.skip("No webhook token")
        r = module_client.get(f"/api/webhooks/{_state['token']}")
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_check_invalid_token(self, module_client: TestClient):
        r = module_client.get("/api/webhooks/invalid")
        assert r.status_code == 404


class TestWebhookHelpers:
    def test_handle_beacon_event(self):
        from app.routers.webhooks import _handle_beacon_event
        db = MagicMock()
        results = {}
        with patch("app.core.db_upsert.upsert_host_by_ip") as mock_upsert, \
             patch("app.routers.webhooks.log_event"), \
             patch("app.routers.webhooks._maybe_create_beacon_cred"):
            host = MagicMock()
            host.id = "h1"
            host.hostname = ""
            host.os = ""
            mock_upsert.return_value = (host, True)
            event = MagicMock(os="Linux", username="admin", source="c2", arch="x64", process="cmd.exe")
            _handle_beacon_event(db, "p1", "10.0.0.1", "test-host", event, results)
        assert results.get("host") in ("created", "updated")

    def test_handle_cred_event(self):
        from app.routers.webhooks import _handle_cred_event
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        results = {}
        event = MagicMock(username="admin", domain="corp.local", secret="pass", hash="", service="ssh")
        with patch("app.routers.webhooks.new_id", return_value="crd1"):
            _handle_cred_event(db, "p1", "10.0.0.1", event, results)
        assert results.get("cred") == "created"

    def test_handle_cred_event_existing(self):
        from app.routers.webhooks import _handle_cred_event
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = MagicMock()
        results = {}
        event = MagicMock(username="admin", domain="corp.local", secret="pass", hash="", service="ssh")
        _handle_cred_event(db, "p1", "10.0.0.1", event, results)
        assert results.get("cred") == "exists"

    def test_handle_finding_event(self):
        from app.routers.webhooks import _handle_finding_event
        db = MagicMock()
        results = {}
        event = MagicMock(title="Vuln", severity="high", description="desc", note="note", source="c2")
        with patch("app.routers.webhooks.new_id", return_value="fnd1"), \
             patch("app.routers.webhooks.log_event"):
            _handle_finding_event(db, "p1", "10.0.0.1", "host1", event, results, "2025-01-01")
        assert results.get("finding") == "created"
