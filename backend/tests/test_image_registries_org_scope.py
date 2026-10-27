"""Org-scoped image registries — org admins can manage their own org's
registry list without needing platform_admin, and one org's list can
never leak into or overwrite another org's (2026-08-18)."""

import pytest
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
USER_PASS = "OrgPass1234!"

_s: dict = {}


def _login(c: TestClient, username: str, password: str = USER_PASS):
    r = c.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, f"login failed for {username}: {r.text}"


def _logout(c: TestClient):
    c.post("/api/auth/logout")


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    c = module_client
    c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    _login(c, ADMIN, ADMIN_PASS)

    r = c.post(
        "/api/admin/users",
        json={"username": "reg_org_admin", "password": USER_PASS, "role": "user"},
    )
    _s["uid"] = r.json()["id"]

    r = c.post("/api/orgs", json={"name": "Registry Org A", "slug": "registry-org-a"})
    _s["org_a"] = r.json()["id"]
    r = c.post("/api/orgs", json={"name": "Registry Org B", "slug": "registry-org-b"})
    _s["org_b"] = r.json()["id"]

    c.post(f"/api/orgs/{_s['org_a']}/members", json={"user_id": _s["uid"], "role": "admin"})
    yield
    c.post("/api/auth/logout")


class TestOrgScopedRegistries:
    def test_org_admin_can_create_registry_in_own_org(self, module_client: TestClient):
        _logout(module_client)
        _login(module_client, "reg_org_admin")
        r = module_client.post(
            f"/api/image-registries?org_id={_s['org_a']}",
            json={"name": "org-a-registry", "url": "registry-a.example.com"},
        )
        assert r.status_code == 200, r.text
        _s["reg_a_id"] = r.json()["id"]
        _logout(module_client)
        _login(module_client, ADMIN, ADMIN_PASS)

    def test_org_admin_cannot_write_other_org_registry(self, module_client: TestClient):
        _logout(module_client)
        _login(module_client, "reg_org_admin")
        r = module_client.post(
            f"/api/image-registries?org_id={_s['org_b']}",
            json={"name": "org-b-registry", "url": "registry-b.example.com"},
        )
        assert r.status_code == 403
        _logout(module_client)
        _login(module_client, ADMIN, ADMIN_PASS)

    def test_org_a_registries_not_visible_under_org_b(self, module_client: TestClient):
        r = module_client.get(f"/api/image-registries?org_id={_s['org_b']}")
        assert r.status_code == 200
        assert all(reg["id"] != _s["reg_a_id"] for reg in r.json())

    def test_non_member_cannot_read_other_org_registries(self, module_client: TestClient):
        # reg_org_admin is only a member of org_a — reading org_b's list
        # by guessing its org_id must be rejected, not silently served.
        _logout(module_client)
        _login(module_client, "reg_org_admin")
        r = module_client.get(f"/api/image-registries?org_id={_s['org_b']}")
        assert r.status_code == 403
        _logout(module_client)
        _login(module_client, ADMIN, ADMIN_PASS)

    def test_non_member_cannot_read_via_workstations_endpoint(self, module_client: TestClient):
        _logout(module_client)
        _login(module_client, "reg_org_admin")
        r = module_client.get(f"/api/workstations/image-registries?org_id={_s['org_b']}")
        assert r.status_code == 403
        _logout(module_client)
        _login(module_client, ADMIN, ADMIN_PASS)

    def test_org_a_registry_visible_under_org_a(self, module_client: TestClient):
        r = module_client.get(f"/api/image-registries?org_id={_s['org_a']}")
        assert r.status_code == 200
        assert any(reg["id"] == _s["reg_a_id"] for reg in r.json())

    def test_platform_wide_list_unaffected(self, module_client: TestClient):
        r = module_client.get("/api/image-registries")
        assert r.status_code == 200
        assert all(reg["id"] != _s["reg_a_id"] for reg in r.json())

    def test_non_admin_cannot_write_platform_wide_list(self, module_client: TestClient):
        _logout(module_client)
        _login(module_client, "reg_org_admin")
        r = module_client.post(
            "/api/image-registries",
            json={"name": "platform-registry", "url": "registry.example.com"},
        )
        assert r.status_code == 403
        _logout(module_client)
        _login(module_client, ADMIN, ADMIN_PASS)
