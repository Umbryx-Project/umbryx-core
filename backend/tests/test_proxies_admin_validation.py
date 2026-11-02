"""proxies_admin: endpoint grammar validation + SSRF-safe checks.

Shannon 2026-10-29 (SSRF-04): host/port/scheme are validated on create
and patch, and check_endpoint grammar-validates test_url so stored
proxy credentials are never attached to arbitrary hosts."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
TS = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200, r.text
    # a valid endpoint to patch and probe
    r = module_client.post(
        "/api/admin/proxies",
        json={"name": "valid proxy", "scheme": "http", "host": "proxy.corp.local", "port": 3128},
    )
    assert r.status_code == 201, r.text
    _state["eid"] = r.json()["id"]
    yield
    module_client.delete(f"/api/admin/proxies/{_state['eid']}")
    module_client.post("/api/auth/logout")


class TestCreateValidation:
    def test_invalid_host_rejected(self, module_client: TestClient):
        r = module_client.post(
            "/api/admin/proxies",
            json={"name": "x", "scheme": "http", "host": "bad host!", "port": 8080},
        )
        assert r.status_code == 400
        assert "invalid host" in r.text.lower()

    def test_unsupported_scheme_rejected(self, module_client: TestClient):
        r = module_client.post(
            "/api/admin/proxies",
            json={"name": "x", "scheme": "gopher", "host": "h.example", "port": 8080},
        )
        assert r.status_code == 400
        assert "unsupported scheme" in r.text.lower()

    def test_valid_endpoint_created(self, module_client: TestClient):
        r = module_client.post(
            "/api/admin/proxies",
            json={"name": "temp ok", "scheme": "socks5", "host": "10.0.0.9", "port": 1080},
        )
        assert r.status_code == 201, r.text
        module_client.delete(f"/api/admin/proxies/{r.json()['id']}")


class TestPatchValidation:
    def test_invalid_host_rejected(self, module_client: TestClient):
        r = module_client.patch(
            f"/api/admin/proxies/{_state['eid']}", json={"host": "not a host"}
        )
        assert r.status_code == 400

    def test_invalid_port_rejected(self, module_client: TestClient):
        r = module_client.patch(f"/api/admin/proxies/{_state['eid']}", json={"port": 70000})
        assert r.status_code == 400

    def test_port_zero_rejected(self, module_client: TestClient):
        r = module_client.patch(f"/api/admin/proxies/{_state['eid']}", json={"port": 0})
        assert r.status_code == 400

    def test_unsupported_scheme_rejected(self, module_client: TestClient):
        r = module_client.patch(
            f"/api/admin/proxies/{_state['eid']}", json={"scheme": "ftp"}
        )
        assert r.status_code == 400

    def test_valid_patch_ok(self, module_client: TestClient):
        r = module_client.patch(
            f"/api/admin/proxies/{_state['eid']}", json={"host": "proxy2.corp.local"}
        )
        assert r.status_code == 200, r.text


class TestCheckEndpoint:
    def test_bad_test_url_scheme_rejected(self, module_client: TestClient):
        with patch("socket.create_connection"):
            r = module_client.post(
                f"/api/admin/proxies/{_state['eid']}/check", json={"test_url": "ftp://x"}
            )
            assert r.status_code == 400

    def test_bad_test_url_host_rejected(self, module_client: TestClient):
        with patch("socket.create_connection"):
            r = module_client.post(
                f"/api/admin/proxies/{_state['eid']}/check", json={"test_url": "http://bad host/"}
            )
            assert r.status_code == 400

    def test_valid_test_url_probes_through_proxy(self, module_client: TestClient):
        resp = MagicMock()
        resp.status_code = 204
        with patch("socket.create_connection"), patch(
            "httpx.AsyncClient"
        ) as client_cls:
            ctx = MagicMock()
            ctx.__aenter__ = AsyncMock(return_value=MagicMock())
            ctx.__aenter__.return_value.get = AsyncMock(return_value=resp)
            ctx.__aexit__ = AsyncMock(return_value=False)
            client_cls.return_value = ctx
            r = module_client.post(
                f"/api/admin/proxies/{_state['eid']}/check",
                json={"test_url": "http://example.com/health"},
            )
            assert r.status_code == 200, r.text
            assert r.json()["ok"] is True
            ctx.__aenter__.return_value.get.assert_awaited_once_with("http://example.com/health")
