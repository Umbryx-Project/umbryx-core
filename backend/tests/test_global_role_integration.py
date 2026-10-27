"""
Integration tests for unified global role enforcement.

Verifies:
- platform_admin can access system API and all projects.
- Regular user with project membership cannot access system API.
- Regular user without membership gets 404 on projects.
"""
import pytest
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
USER_PASS = "GlobalPass1234!"

_s: dict = {}


def _login(c: TestClient, username: str, password: str = USER_PASS):
    r = c.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, f"login failed for {username}: {r.text}"


def _logout(c: TestClient):
    c.post("/api/auth/logout")


def _create_user(c: TestClient, username: str, role: str = "user"):
    r = c.post("/api/admin/users", json={
        "username": username, "password": USER_PASS, "role": role,
    })
    assert r.status_code in (200, 201), f"create user {username}: {r.text}"
    return r.json()["id"]


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    c = module_client
    c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    _login(c, ADMIN, ADMIN_PASS)

    r = c.post("/api/projects", json={"name": "Global Role Test", "added": "2025-01-01T00:00:00Z", "status": "active"})
    _s["pid"] = r.json()["id"]

    _s["platadmin_uid"] = _create_user(c, "global_platadmin", "platform_admin")
    _s["regular_uid"] = _create_user(c, "global_regular", "user")

    r = c.post(f"/api/projects/{_s['pid']}/members", json={"user_id": _s["regular_uid"], "role": "operator"})
    assert r.status_code in (200, 201)

    yield
    c.post("/api/auth/logout")


class TestPlatformAdminGlobalRole:
    def test_can_access_system_health(self, module_client: TestClient):
        _logout(module_client)
        _login(module_client, "global_platadmin")
        r = module_client.get("/api/system/health")
        assert r.status_code == 200
        _logout(module_client)
        _login(module_client, ADMIN, ADMIN_PASS)

    def test_can_access_system_logs(self, module_client: TestClient):
        _logout(module_client)
        _login(module_client, "global_platadmin")
        r = module_client.get("/api/system/logs")
        assert r.status_code == 200
        _logout(module_client)
        _login(module_client, ADMIN, ADMIN_PASS)


class TestRegularGlobalRole:
    def test_blocked_from_system_health(self, module_client: TestClient):
        _logout(module_client)
        _login(module_client, "global_regular")
        r = module_client.get("/api/system/health")
        assert r.status_code == 403
        _logout(module_client)
        _login(module_client, ADMIN, ADMIN_PASS)

    def test_blocked_from_system_logs(self, module_client: TestClient):
        _logout(module_client)
        _login(module_client, "global_regular")
        r = module_client.get("/api/system/logs")
        assert r.status_code == 403
        _logout(module_client)
        _login(module_client, ADMIN, ADMIN_PASS)

    def test_can_access_project_as_member(self, module_client: TestClient):
        _logout(module_client)
        _login(module_client, "global_regular")
        r = module_client.get("/api/hosts", params={"pid": _s["pid"]})
        assert r.status_code == 200
        _logout(module_client)
        _login(module_client, ADMIN, ADMIN_PASS)

    def test_blocked_from_project_without_membership(self, module_client: TestClient):
        _create_user(module_client, "global_nonmember", "user")
        _logout(module_client)
        _login(module_client, "global_nonmember")
        r = module_client.get("/api/hosts", params={"pid": _s["pid"]})
        assert r.status_code == 404
        _logout(module_client)
        _login(module_client, ADMIN, ADMIN_PASS)
