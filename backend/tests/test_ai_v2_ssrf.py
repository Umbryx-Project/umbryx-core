"""ai_v2 provider endpoints: SSRF grammar + AI chat ownership.

Shannon 2026-10-29 router hardening: stored provider base_urls are
grammar-checked (private hosts stay allowed for on-LAN LLM endpoints),
stateless fetch-models only reaches public endpoints, and one user's
AI chats are invisible to another non-admin user without project
admin rights."""

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
MEMBER = "ai_ssrf_member"
MEMBER_PASS = "Pass1234!ssrf"
TS = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200, r.text
    r = module_client.post("/api/projects", json={"name": "AI SSRF Test", "added": TS})
    assert r.status_code in (200, 201), r.text
    _state["pid"] = r.json()["id"]
    r = module_client.post(
        "/api/admin/users", json={"username": MEMBER, "password": MEMBER_PASS, "role": "user"}
    )
    assert r.status_code in (201, 409), r.text
    if r.status_code == 201:
        _state["member_id"] = r.json()["id"]
    else:
        users = module_client.get("/api/admin/users").json()
        _state["member_id"] = next(u["id"] for u in users if u["username"] == MEMBER)
    # viewer: can read the project (findings.read) but is not project admin
    r = module_client.post(
        f"/api/projects/{_state['pid']}/members",
        json={"user_id": _state["member_id"], "role": "viewer"},
    )
    assert r.status_code in (200, 201, 409), r.text
    # admin's chat in that project (owned by admin)
    r = module_client.post(f"/api/projects/{_state['pid']}/ai/chats", json={"title": "admin chat"})
    assert r.status_code in (200, 201), r.text
    _state["admin_chat"] = r.json()["id"]
    yield
    module_client.post("/api/auth/logout")


def _login(client: TestClient, username: str, password: str):
    client.post("/api/auth/logout")
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text


def _login_admin(client: TestClient):
    _login(client, ADMIN, ADMIN_PASS)


class TestProviderBaseUrlValidation:
    def test_bad_scheme_rejected(self, module_client: TestClient):
        r = module_client.post(
            "/api/ai/providers",
            json={"id": "ssrfprov1", "provider": "openai", "base_url": "ftp://evil.example"},
        )
        assert r.status_code == 400
        assert "scheme" in r.text.lower()

    def test_no_hostname_rejected(self, module_client: TestClient):
        r = module_client.post(
            "/api/ai/providers",
            json={"id": "ssrfprov2", "provider": "openai", "base_url": "definitely not a url"},
        )
        assert r.status_code == 400

    def test_private_lan_endpoint_still_allowed(self, module_client: TestClient):
        # on-LAN LLM proxies (Ollama) are admin-configured and legitimate
        r = module_client.post(
            "/api/ai/providers",
            json={
                "id": "ssrfprov_lan",
                "name": "lan ollama",
                "provider": "ollama",
                "base_url": "http://127.0.0.1:11434",
            },
        )
        assert r.status_code in (200, 201), r.text
        _state["lan_provider"] = r.json()["id"]

    def test_update_with_bad_url_rejected(self, module_client: TestClient):
        pid = _state["lan_provider"]
        r = module_client.put(f"/api/ai/providers/{pid}", json={"base_url": "gopher://x"})
        assert r.status_code == 400

    def test_update_with_valid_url_ok(self, module_client: TestClient):
        pid = _state["lan_provider"]
        r = module_client.put(
            f"/api/ai/providers/{pid}", json={"base_url": "http://10.10.10.10:11434"}
        )
        assert r.status_code == 200, r.text

    def test_delete_provider(self, module_client: TestClient):
        r = module_client.delete(f"/api/ai/providers/{_state['lan_provider']}")
        assert r.status_code in (200, 204), r.text


class TestFetchModelsPublicOnly:
    def test_private_url_rejected_stateless_fetch(self, module_client: TestClient):
        r = module_client.post(
            "/api/ai/providers/fetch-models",
            json={"provider": "openai", "base_url": "http://127.0.0.1:11434", "api_key": "sk-x"},
        )
        assert r.status_code == 400
        assert "private" in r.text.lower() or "400" in r.text

    def test_metadata_endpoint_rejected(self, module_client: TestClient):
        r = module_client.post(
            "/api/ai/providers/fetch-models",
            json={
                "provider": "openai",
                "base_url": "http://169.254.169.254/latest/meta-data",
                "api_key": "sk-x",
            },
        )
        assert r.status_code == 400


class TestChatVisibility:
    def test_foreign_chat_hidden_from_non_admin_member(self, module_client: TestClient):
        _login(module_client, MEMBER, MEMBER_PASS)
        r = module_client.get(
            f"/api/projects/{_state['pid']}/ai/chats/{_state['admin_chat']}"
        )
        assert r.status_code == 404
        r = module_client.delete(
            f"/api/projects/{_state['pid']}/ai/chats/{_state['admin_chat']}"
        )
        assert r.status_code == 404

    def test_own_chat_visible_to_member(self, module_client: TestClient):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/ai/chats", json={"title": "member chat"}
        )
        assert r.status_code in (200, 201), r.text
        cid = r.json()["id"]
        r = module_client.get(f"/api/projects/{_state['pid']}/ai/chats/{cid}")
        assert r.status_code == 200
        r = module_client.delete(f"/api/projects/{_state['pid']}/ai/chats/{cid}")
        assert r.status_code == 200
        _login_admin(module_client)

    def test_admin_sees_every_chat(self, module_client: TestClient):
        r = module_client.get(
            f"/api/projects/{_state['pid']}/ai/chats/{_state['admin_chat']}"
        )
        assert r.status_code == 200
