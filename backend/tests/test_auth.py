"""Tests for authentication endpoints."""
from fastapi.testclient import TestClient


def test_auth_status_uninitialized(client: TestClient):
    resp = client.get("/api/auth/status")
    assert resp.status_code == 200
    data = resp.json()
    assert "initialized" in data


def test_setup_creates_admin(client: TestClient):
    resp = client.post("/api/auth/setup", json={"username": "admin", "password": "TestPass1234!"})  # NOSONAR
    # Either 201 (first setup) or 403 (already initialized)
    assert resp.status_code in (201, 403)


def test_login_wrong_password(client: TestClient):
    # Ensure user exists first
    client.post("/api/auth/setup", json={"username": "admin", "password": "TestPass1234!"})  # NOSONAR
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "wrongpassword"})  # NOSONAR
    assert resp.status_code == 401


def test_login_nonexistent_user(client: TestClient):
    resp = client.post("/api/auth/login", json={"username": "nobody", "password": "pass"})  # NOSONAR
    assert resp.status_code == 401


def test_me_without_token(client: TestClient):
    resp = client.get("/api/auth/me")
    assert resp.status_code == 401


def test_protected_endpoint_without_token(client: TestClient):
    resp = client.get("/api/notes")
    assert resp.status_code == 401


def test_health_endpoint_public(client: TestClient):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] in ("ok", "degraded")


# ════════ from test_auth_final.py ════════
import pytest


@pytest.fixture(scope="module", autouse=True)
def _auth_final_setup(module_client):
    module_client.post("/api/auth/setup", json={"username": "admin", "password": "TestPass1234!"})
    r = module_client.post("/api/auth/login", json={"username": "admin", "password": "TestPass1234!"})
    assert r.status_code == 200, f"login: {r.status_code} {r.text}"
    yield
    module_client.post("/api/auth/logout")


class TestAuthMe:
    def test_me(self, module_client):
        r = module_client.get("/api/auth/me")
        assert r.status_code == 200
        data = r.json()
        assert data["username"] == "admin"

    def test_update_me(self, module_client):
        r = module_client.patch("/api/auth/me", json={"display_name": "Admin User"})
        assert r.status_code == 200
        assert r.json()["display_name"] == "Admin User"

    def test_update_me_empty(self, module_client):
        r = module_client.patch("/api/auth/me", json={"display_name": ""})
        assert r.status_code == 400


class TestAuthChangePassword:
    def test_wrong_current(self, module_client):
        r = module_client.post("/api/auth/change-password", json={"current_password": "wrong", "new_password": "NewPass1234!"})
        assert r.status_code == 400

    def test_same_password(self, module_client):
        r = module_client.post("/api/auth/change-password", json={"current_password": "TestPass1234!", "new_password": "TestPass1234!"})
        assert r.status_code == 400

    def test_too_short(self, module_client):
        r = module_client.post("/api/auth/change-password", json={"current_password": "TestPass1234!", "new_password": "ab"})
        assert r.status_code in (400, 422)


class TestAuthLogout:
    def test_logout_and_relogin(self, module_client):
        r = module_client.post("/api/auth/logout")
        assert r.status_code == 204
        r = module_client.post("/api/auth/login", json={"username": "admin", "password": "TestPass1234!"})
        assert r.status_code == 200


class TestAuthStreamToken:
    def test_stream_token_issued(self, module_client):
        # Regression: this imported a nonexistent ..core.auth module and
        # 500'd on every call, silently breaking SSE/EventSource auth
        # (security retest, 2026-09-03).
        r = module_client.post("/api/auth/stream-token")
        assert r.status_code == 200, r.text
        assert r.json()["token"]

    def test_stream_token_rejected_as_bearer_auth(self, module_client):
        token = module_client.post("/api/auth/stream-token").json()["token"]
        r = module_client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 401


class TestAuthStatus:
    def test_status(self, module_client):
        r = module_client.get("/api/auth/status")
        assert r.status_code == 200
        assert r.json()["initialized"] is True
