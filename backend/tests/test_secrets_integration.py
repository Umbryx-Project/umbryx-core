"""
Phase 2 — Integration tests for Project Secrets Vault.
"""
import pytest
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
USER_PASS = "SecretPass1234!"

_s: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    c = module_client
    c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = c.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200

    r = c.post("/api/admin/users", json={"username": "sec_operator", "password": USER_PASS, "role": "user"})
    assert r.status_code in (200, 201)
    _s["op_uid"] = r.json()["id"]

    r = c.post("/api/projects", json={"name": "Secrets Test", "added": "2025-01-01T00:00:00Z", "status": "active"})
    _s["pid"] = r.json()["id"]

    c.post(f"/api/projects/{_s['pid']}/members", json={"user_id": _s["op_uid"], "role": "operator"})
    yield
    c.post("/api/auth/logout")


def _as(c: TestClient, username: str):
    c.post("/api/auth/logout")
    r = c.post("/api/auth/login", json={"username": username, "password": USER_PASS})
    assert r.status_code == 200


def _as_admin(c: TestClient):
    c.post("/api/auth/logout")
    r = c.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200


class TestSecretCRUD:
    def test_create_secret(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_s['pid']}/secrets", json={
            "kind": "api_token", "name": "Hetzner Token", "value": "super-secret-token-123",
            "meta": {"provider": "hetzner"},
        })
        assert r.status_code == 201
        data = r.json()
        assert data["kind"] == "api_token"
        assert data["name"] == "Hetzner Token"
        assert data["status"] == "active"
        assert "value" not in data
        _s["sec_id"] = data["id"]

    def test_list_secrets(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_s['pid']}/secrets")
        assert r.status_code == 200
        assert any(s["id"] == _s["sec_id"] for s in r.json())

    def test_get_secret(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_s['pid']}/secrets/{_s['sec_id']}")
        assert r.status_code == 200
        assert r.json()["kind"] == "api_token"

    def test_update_secret(self, module_client: TestClient):
        r = module_client.patch(f"/api/projects/{_s['pid']}/secrets/{_s['sec_id']}", json={
            "name": "Updated Token", "value": "new-token-456",
        })
        assert r.status_code == 200
        assert r.json()["name"] == "Updated Token"

    def test_invalid_kind(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_s['pid']}/secrets", json={
            "kind": "invalid_kind", "name": "Bad", "value": "x",
        })
        assert r.status_code == 400


class TestSecretDownload:
    def test_download_secret(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_s['pid']}/secrets/{_s['sec_id']}/download")
        assert r.status_code == 200
        assert r.headers["content-disposition"].startswith("attachment")
        assert b"new-token-456" in r.content

    def test_operator_cannot_download(self, module_client: TestClient):
        _as(module_client, "sec_operator")
        r = module_client.get(f"/api/projects/{_s['pid']}/secrets/{_s['sec_id']}/download")
        assert r.status_code == 403
        _as_admin(module_client)


class TestSecretRevoke:
    def test_revoke_secret(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_s['pid']}/secrets/{_s['sec_id']}/revoke")
        assert r.status_code == 200
        assert r.json()["status"] == "revoked"

    def test_cannot_download_revoked(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_s['pid']}/secrets/{_s['sec_id']}/download")
        assert r.status_code == 400

    def test_cannot_update_revoked(self, module_client: TestClient):
        r = module_client.patch(f"/api/projects/{_s['pid']}/secrets/{_s['sec_id']}", json={"name": "Nope"})
        assert r.status_code == 400

    def test_cannot_revoke_twice(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_s['pid']}/secrets/{_s['sec_id']}/revoke")
        assert r.status_code == 400


class TestSecretDelete:
    def test_delete_secret(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_s['pid']}/secrets", json={
            "kind": "password", "name": "Temp Pass", "value": "temp123",
        })
        sid = r.json()["id"]
        r = module_client.delete(f"/api/projects/{_s['pid']}/secrets/{sid}")
        assert r.status_code == 204

    def test_delete_nonexistent(self, module_client: TestClient):
        r = module_client.delete(f"/api/projects/{_s['pid']}/secrets/nonexistent")
        assert r.status_code == 404


class TestSSHKeyGeneration:
    def test_generate_ssh_key(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_s['pid']}/secrets/generate-ssh", json={
            "name": "Team SSH Key", "issued_to": "operator1",
        })
        assert r.status_code == 201
        data = r.json()
        assert data["kind"] == "ssh_key"
        assert data["status"] == "active"
        assert "public_key" in data["meta"]
        assert data["meta"]["public_key"].startswith("ssh-ed25519")
        assert "fingerprint" in data["meta"]
        _s["ssh_id"] = data["id"]

    def test_download_ssh_key(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_s['pid']}/secrets/{_s['ssh_id']}/download")
        assert r.status_code == 200
        assert b"BEGIN OPENSSH PRIVATE KEY" in r.content
        assert r.headers["content-disposition"].__contains__("id_ed25519")

    def test_operator_cannot_generate(self, module_client: TestClient):
        _as(module_client, "sec_operator")
        r = module_client.post(f"/api/projects/{_s['pid']}/secrets/generate-ssh", json={"name": "Nope"})
        assert r.status_code == 403
        _as_admin(module_client)
