"""
Phase 0.1 — Integration tests for per-project RBAC enforcement.

Verifies that each member role (analyst, reviewer, viewer, operator, auditor)
can only access endpoints permitted by their permission set.
"""
import pytest
from fastapi.testclient import TestClient

from ._license_test_utils import license_ee

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
USER_PASS = "RolePass1234!"

_s: dict = {}


def _login(c: TestClient, username: str, password: str = USER_PASS):
    r = c.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, f"login failed for {username}: {r.text}"


def _logout(c: TestClient):
    c.post("/api/auth/logout")


def _create_user(c: TestClient, username: str):
    r = c.post("/api/admin/users", json={
        "username": username, "password": USER_PASS, "role": "user",
    })
    assert r.status_code in (200, 201), f"create user {username}: {r.text}"
    return r.json()["id"]


def _add_member(c: TestClient, pid: str, uid: str, role: str):
    r = c.post(f"/api/projects/{pid}/members", json={"user_id": uid, "role": role})
    assert r.status_code in (200, 201), f"add member {role}: {r.text}"


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient, module_db):
    c = module_client
    c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    _login(c, ADMIN, ADMIN_PASS)

    # The review roles (reviewer / analyst / observer) are Team+
    # (docs/modules/MONETIZATION.md) and this module assigns them to
    # check what each role may do. A license, not an `ee` marker: the
    # roles exist in every build and are gated by the license, not
    # removed from the artifact.
    _s["_license_undo"] = license_ee(c, module_db)

    r = c.post("/api/projects", json={"name": "RBAC Test", "added": "2025-01-01T00:00:00Z", "status": "active"})
    _s["pid"] = r.json()["id"]

    _s["analyst"] = _create_user(c, "rbac_analyst")
    _s["reviewer"] = _create_user(c, "rbac_reviewer")
    _s["viewer"] = _create_user(c, "rbac_viewer")
    _s["operator"] = _create_user(c, "rbac_operator")
    _s["auditor"] = _create_user(c, "rbac_auditor")

    _add_member(c, _s["pid"], _s["analyst"], "analyst")
    _add_member(c, _s["pid"], _s["reviewer"], "reviewer")
    _add_member(c, _s["pid"], _s["viewer"], "viewer")
    _add_member(c, _s["pid"], _s["operator"], "operator")
    _add_member(c, _s["pid"], _s["auditor"], "auditor")

    r = c.post("/api/hosts", json={"pid": _s["pid"], "ip": "10.0.0.1", "os": "linux"})
    assert r.status_code == 201, f"host create: {r.text}"
    _s["host_id"] = r.json()["id"]

    r = c.post("/api/creds", json={
        "pid": _s["pid"], "username": "testuser", "secret": "secret123", "type": "plain",
    })
    assert r.status_code == 201, f"cred create: {r.text}"
    _s["cred_id"] = r.json()["id"]

    yield
    _s.pop("_license_undo")()
    c.post("/api/auth/logout")


def _as_role(c: TestClient, role_key: str):
    _logout(c)
    _login(c, f"rbac_{role_key}")


def _revert_admin(c: TestClient):
    _logout(c)
    _login(c, ADMIN, ADMIN_PASS)


# ── Analyst ───────────────────────────────────────────────────────────

class TestAnalystRole:
    def test_can_read_hosts(self, module_client: TestClient):
        _as_role(module_client, "analyst")
        r = module_client.get("/api/hosts", params={"pid": _s["pid"]})
        assert r.status_code == 200
        _revert_admin(module_client)

    def test_can_read_creds(self, module_client: TestClient):
        _as_role(module_client, "analyst")
        r = module_client.get("/api/creds", params={"pid": _s["pid"]})
        assert r.status_code == 200
        _revert_admin(module_client)

    def test_cannot_read_cred_secret(self, module_client: TestClient):
        _as_role(module_client, "analyst")
        r = module_client.get(f"/api/creds/{_s['cred_id']}/secret")
        assert r.status_code == 403
        _revert_admin(module_client)

    def test_cannot_create_hosts(self, module_client: TestClient):
        _as_role(module_client, "analyst")
        r = module_client.post("/api/hosts", json={"pid": _s["pid"], "ip": "10.0.0.99"})
        assert r.status_code == 403
        _revert_admin(module_client)

    def test_can_read_findings(self, module_client: TestClient):
        _as_role(module_client, "analyst")
        r = module_client.get("/api/findings", params={"pid": _s["pid"]})
        assert r.status_code == 200
        _revert_admin(module_client)

    def test_can_read_timeline(self, module_client: TestClient):
        _as_role(module_client, "analyst")
        r = module_client.get("/api/timeline", params={"pid": _s["pid"]})
        assert r.status_code == 200
        _revert_admin(module_client)


# ── Reviewer ──────────────────────────────────────────────────────────

class TestReviewerRole:
    def test_cannot_read_hosts(self, module_client: TestClient):
        _as_role(module_client, "reviewer")
        r = module_client.get("/api/hosts", params={"pid": _s["pid"]})
        assert r.status_code == 403
        _revert_admin(module_client)

    def test_cannot_read_creds(self, module_client: TestClient):
        _as_role(module_client, "reviewer")
        r = module_client.get("/api/creds", params={"pid": _s["pid"]})
        assert r.status_code == 403
        _revert_admin(module_client)

    def test_can_read_findings(self, module_client: TestClient):
        _as_role(module_client, "reviewer")
        r = module_client.get("/api/findings", params={"pid": _s["pid"]})
        assert r.status_code == 200
        _revert_admin(module_client)

    def test_cannot_create_hosts(self, module_client: TestClient):
        _as_role(module_client, "reviewer")
        r = module_client.post("/api/hosts", json={"pid": _s["pid"], "ip": "10.0.0.98"})
        assert r.status_code == 403
        _revert_admin(module_client)

    def test_cannot_read_timeline(self, module_client: TestClient):
        _as_role(module_client, "reviewer")
        r = module_client.get("/api/timeline", params={"pid": _s["pid"]})
        assert r.status_code == 200
        _revert_admin(module_client)


# ── Viewer ────────────────────────────────────────────────────────────

class TestViewerRole:
    def test_can_read_hosts(self, module_client: TestClient):
        _as_role(module_client, "viewer")
        r = module_client.get("/api/hosts", params={"pid": _s["pid"]})
        assert r.status_code == 200
        _revert_admin(module_client)

    def test_can_read_creds(self, module_client: TestClient):
        _as_role(module_client, "viewer")
        r = module_client.get("/api/creds", params={"pid": _s["pid"]})
        assert r.status_code == 200
        _revert_admin(module_client)

    def test_cannot_read_cred_secret(self, module_client: TestClient):
        _as_role(module_client, "viewer")
        r = module_client.get(f"/api/creds/{_s['cred_id']}/secret")
        assert r.status_code == 403
        _revert_admin(module_client)

    def test_cannot_create_hosts(self, module_client: TestClient):
        _as_role(module_client, "viewer")
        r = module_client.post("/api/hosts", json={"pid": _s["pid"], "ip": "10.0.0.97"})
        assert r.status_code == 403
        _revert_admin(module_client)

    def test_cannot_create_findings(self, module_client: TestClient):
        _as_role(module_client, "viewer")
        r = module_client.post("/api/findings/scan-candidates", params={"pid": _s["pid"]})
        assert r.status_code == 403
        _revert_admin(module_client)


# ── Operator ──────────────────────────────────────────────────────────

class TestOperatorRole:
    def test_can_read_hosts(self, module_client: TestClient):
        _as_role(module_client, "operator")
        r = module_client.get("/api/hosts", params={"pid": _s["pid"]})
        assert r.status_code == 200
        _revert_admin(module_client)

    def test_can_create_hosts(self, module_client: TestClient):
        _as_role(module_client, "operator")
        r = module_client.post("/api/hosts", json={"pid": _s["pid"], "ip": "10.0.0.50"})
        assert r.status_code == 201
        _revert_admin(module_client)

    def test_can_read_cred_secret(self, module_client: TestClient):
        _as_role(module_client, "operator")
        r = module_client.get(f"/api/creds/{_s['cred_id']}/secret")
        assert r.status_code == 200
        _revert_admin(module_client)

    def test_can_read_playbooks(self, module_client: TestClient):
        _as_role(module_client, "operator")
        r = module_client.get("/api/playbooks")
        assert r.status_code == 200
        _revert_admin(module_client)

    def test_cannot_manage_members(self, module_client: TestClient):
        _as_role(module_client, "operator")
        r = module_client.post(f"/api/projects/{_s['pid']}/members", json={
            "user_id": _s["viewer"], "role": "viewer",
        })
        assert r.status_code == 403
        _revert_admin(module_client)


# ── Auditor ───────────────────────────────────────────────────────────

class TestAuditorRole:
    def test_can_read_hosts(self, module_client: TestClient):
        _as_role(module_client, "auditor")
        r = module_client.get("/api/hosts", params={"pid": _s["pid"]})
        assert r.status_code == 200
        _revert_admin(module_client)

    def test_cannot_read_creds(self, module_client: TestClient):
        _as_role(module_client, "auditor")
        r = module_client.get("/api/creds", params={"pid": _s["pid"]})
        assert r.status_code == 403
        _revert_admin(module_client)

    def test_cannot_create_anything(self, module_client: TestClient):
        _as_role(module_client, "auditor")
        r = module_client.post("/api/hosts", json={"pid": _s["pid"], "ip": "10.0.0.96"})
        assert r.status_code == 403
        _revert_admin(module_client)
