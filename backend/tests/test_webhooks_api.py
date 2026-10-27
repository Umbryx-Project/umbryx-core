"""Webhooks API integration tests — token management, event ingestion."""
import hashlib
import hmac
import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
TS = "2025-01-01T00:00:00Z"
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

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200, r.text
    r = module_client.post("/api/projects", json={"name": "Webhooks Test", "added": TS, "status": "active"})
    assert r.status_code == 201, r.text
    _state["pid"] = r.json()["id"]
    yield
    module_client.post("/api/auth/logout")


class TestWebhookToken:
    def test_get_webhook_initially_empty(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/webhook")
        assert r.status_code == 200
        data = r.json()
        assert "token" in data
        assert "url" in data

    def test_regenerate_webhook_token(self, module_client: TestClient):
        # regenerate_webhook_token() fail-closes without WEBHOOK_HMAC_SECRET
        # (security audit finding F11); patch just for this call so the
        # ingestion tests below still exercise the no-HMAC-configured path.
        with patch("app.routers.webhooks.WEBHOOK_HMAC_SECRET", "test-hmac-secret"):
            r = module_client.post(f"/api/projects/{_state['pid']}/webhook/regenerate")
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["token"]
        assert data["url"]
        _state["token"] = data["token"]

    def test_get_webhook_after_regenerate(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_state['pid']}/webhook")
        assert r.status_code == 200
        assert r.json()["token"] == _state["token"]

    def test_webhook_nonexistent_project_404(self, module_client: TestClient):
        r = module_client.get("/api/projects/prj_nonexistent/webhook")
        assert r.status_code == 404


class TestWebhookIngestion:
    def test_receive_beacon_event_creates_host_and_note(self, module_client: TestClient):
        # Regression: _handle_beacon_event used to pass a "notes" default
        # into upsert_host_by_ip for a column migration 076 already
        # dropped from `hosts` — always crashed the INSERT path against a
        # real Postgres schema (SQLite's create_all-per-test-run schema
        # never caught this drift). Beacon enrichment text now goes into a
        # real Note instead.
        token = _state["token"]
        r = _signed_post(module_client, f"/api/webhooks/{token}", {
            "type": "beacon",
            "ip": "10.0.99.1",
            "hostname": "beacon-host",
            "os": "Linux",
            "source": "cobaltstrike",
            "process": "svchost.exe",
            "arch": "x64",
        })
        assert r.status_code == 200, r.text
        assert r.json()["results"]["host"] == "created"

    def test_receive_cred_event(self, module_client: TestClient):
        token = _state["token"]
        r = _signed_post(module_client, f"/api/webhooks/{token}", {
            "type": "cred",
            "username": "svc_admin",
            "secret": "NTHash12345",
            "domain": "corp.local",
            "ip": "10.0.0.50",
        })
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["ok"] is True

    def test_receive_finding_event(self, module_client: TestClient):
        token = _state["token"]
        r = _signed_post(module_client, f"/api/webhooks/{token}", {
            "type": "finding",
            "title": "Privilege Escalation",
            "severity": "critical",
            "ip": "10.0.0.50",
            "description": "Local admin obtained",
        })
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["ok"] is True
        assert "finding" in data["results"]

    def test_receive_cred_event_duplicate(self, module_client: TestClient):
        token = _state["token"]
        r = _signed_post(module_client, f"/api/webhooks/{token}", {
            "type": "cred",
            "username": "svc_admin",
            "secret": "NTHash12345",
            "domain": "corp.local",
            "ip": "10.0.0.50",
        })
        assert r.status_code == 200
        assert r.json()["results"].get("cred") in ("created", "exists")

    def test_receive_implant_event_no_ip(self, module_client: TestClient):
        token = _state["token"]
        r = _signed_post(module_client, f"/api/webhooks/{token}", {
            "type": "implant",
        })
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_invalid_token_404(self, module_client: TestClient):
        r = _signed_post(module_client, "/api/webhooks/invalid_token_xyz", {
            "type": "beacon",
            "ip": "10.0.0.1",
        })
        assert r.status_code == 404


class TestWebhookHmacEnforced:
    """Security audit finding F11: an unconfigured/missing/invalid HMAC
    signature must be rejected outright, not silently accepted just
    because the token in the URL matched."""

    def test_no_signature_header_rejected(self, module_client: TestClient):
        token = _state["token"]
        with patch("app.routers.webhooks.WEBHOOK_HMAC_SECRET", HMAC_SECRET):
            r = module_client.post(f"/api/webhooks/{token}", json={"type": "beacon", "ip": "10.0.0.1"})
        assert r.status_code == 403

    def test_wrong_signature_rejected(self, module_client: TestClient):
        token = _state["token"]
        body = json.dumps({"type": "beacon", "ip": "10.0.0.1"}).encode()
        with patch("app.routers.webhooks.WEBHOOK_HMAC_SECRET", HMAC_SECRET):
            r = module_client.post(
                f"/api/webhooks/{token}",
                content=body,
                headers={"Content-Type": "application/json", "X-Hub-Signature-256": "sha256=deadbeef"},
            )
        assert r.status_code == 403

    def test_no_secret_configured_rejects_even_valid_looking_signature(self, module_client: TestClient):
        # WEBHOOK_HMAC_SECRET unset (test default) — this used to be treated
        # as "verification not required" and accepted on token alone.
        token = _state["token"]
        body = json.dumps({"type": "beacon", "ip": "10.0.0.1"}).encode()
        sig = "sha256=" + hmac.new(HMAC_SECRET.encode(), body, hashlib.sha256).hexdigest()
        r = module_client.post(
            f"/api/webhooks/{token}",
            content=body,
            headers={"Content-Type": "application/json", "X-Hub-Signature-256": sig},
        )
        assert r.status_code == 403


class TestCheckWebhookToken:
    def test_check_valid_token(self, module_client: TestClient):
        r = module_client.get(f"/api/webhooks/{_state['token']}")
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert "project" in data

    def test_check_invalid_token_404(self, module_client: TestClient):
        r = module_client.get("/api/webhooks/invalid_token_xyz")
        assert r.status_code == 404
