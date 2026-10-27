"""
IOC Tracker project scoping (audit 2026-08-31, finding 4.1.5).

The module router used to be project-blind: any authenticated user could
read/create/edit/delete IOCs of every project. Now every endpoint is
mounted under /api/projects/{pid}/ext/ioc-tracker, requires project
membership and filters by project_id.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
USER_PASS = "IocPass1234!"

_s: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient, module_db: Session):
    c = module_client
    c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    c.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})

    r = c.post("/api/projects", json={"name": "IOC A", "added": "2025-01-01T00:00:00Z", "status": "active"})
    _s["pid_a"] = r.json()["id"]
    r = c.post("/api/projects", json={"name": "IOC B", "added": "2025-01-01T00:00:00Z", "status": "active"})
    _s["pid_b"] = r.json()["id"]

    # Plain user, member of A only (viewer)
    r = c.post("/api/admin/users", json={"username": "ioc_member", "password": USER_PASS, "role": "user"})
    _s["member_uid"] = r.json()["id"]
    c.post(f"/api/projects/{_s['pid_a']}/members", json={
        "user_id": _s["member_uid"], "role": "viewer",
    })

    # Two IOCs: one per project, created by the admin
    for pid, value in ((_s["pid_a"], "10.10.10.10"), (_s["pid_b"], "10.20.20.20")):
        r = c.post(f"/api/projects/{pid}/ext/ioc-tracker/iocs", json={"value": value, "ioc_type": "ip"})
        assert r.status_code in (200, 201), r.text
        _s[f"ioc_{value}"] = r.json()["id"]
    yield
    c.post("/api/auth/logout")


def _login_member(module_client):
    module_client.post("/api/auth/logout")
    module_client.post("/api/auth/login", json={"username": "ioc_member", "password": USER_PASS})


def _login_admin(module_client):
    module_client.post("/api/auth/logout")
    module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})


class TestIocTrackerProjectIsolation:
    def test_member_lists_only_own_project(self, module_client: TestClient):
        _login_member(module_client)
        r = module_client.get(f"/api/projects/{_s['pid_a']}/ext/ioc-tracker/iocs")
        assert r.status_code == 200
        items = r.json()["items"]
        assert all(i["project_id"] == _s["pid_a"] for i in items)
        assert any(i["id"] == _s["ioc_10.10.10.10"] for i in items)
        assert all(i["id"] != _s["ioc_10.20.20.20"] for i in items)

    def test_member_cannot_access_other_project(self, module_client: TestClient):
        _login_member(module_client)
        r = module_client.get(f"/api/projects/{_s['pid_b']}/ext/ioc-tracker/iocs")
        assert r.status_code == 404  # not a member of B
        r = module_client.get(f"/api/projects/{_s['pid_b']}/ext/ioc-tracker/summary")
        assert r.status_code == 404

    def test_cross_project_id_confusion_returns_404(self, module_client: TestClient):
        """IOC of project B fetched through project A's path → 404, not data."""
        _login_member(module_client)
        r = module_client.get(
            f"/api/projects/{_s['pid_a']}/ext/ioc-tracker/iocs/{_s['ioc_10.20.20.20']}"
        )
        assert r.status_code == 404
        r = module_client.patch(
            f"/api/projects/{_s['pid_a']}/ext/ioc-tracker/iocs/{_s['ioc_10.20.20.20']}",
            json={"status": "contained"},
        )
        assert r.status_code == 404
        r = module_client.delete(
            f"/api/projects/{_s['pid_a']}/ext/ioc-tracker/iocs/{_s['ioc_10.20.20.20']}"
        )
        assert r.status_code == 404

    def test_member_cannot_create_in_foreign_project(self, module_client: TestClient):
        _login_member(module_client)
        r = module_client.post(
            f"/api/projects/{_s['pid_b']}/ext/ioc-tracker/iocs",
            json={"value": "9.9.9.9", "ioc_type": "ip"},
        )
        assert r.status_code == 404

    def test_member_crud_in_own_project(self, module_client: TestClient):
        _login_member(module_client)
        r = module_client.post(
            f"/api/projects/{_s['pid_a']}/ext/ioc-tracker/iocs",
            json={"value": "evil.example.com", "ioc_type": "domain", "severity": "high"},
        )
        assert r.status_code in (200, 201), r.text
        ioc_id = r.json()["id"]
        assert r.json()["project_id"] == _s["pid_a"]

        r = module_client.patch(
            f"/api/projects/{_s['pid_a']}/ext/ioc-tracker/iocs/{ioc_id}",
            json={"status": "contained"},
        )
        assert r.status_code == 200
        assert r.json()["data"]["status"] == "contained"

        r = module_client.get(f"/api/projects/{_s['pid_a']}/ext/ioc-tracker/summary")
        assert r.status_code == 200
        assert r.json()["total"] >= 2

        r = module_client.delete(
            f"/api/projects/{_s['pid_a']}/ext/ioc-tracker/iocs/{ioc_id}"
        )
        assert r.status_code == 200

    def test_summary_is_project_scoped(self, module_client: TestClient):
        _login_admin(module_client)
        ra = module_client.get(f"/api/projects/{_s['pid_a']}/ext/ioc-tracker/summary").json()
        rb = module_client.get(f"/api/projects/{_s['pid_b']}/ext/ioc-tracker/summary").json()
        assert ra["total"] >= 1 and rb["total"] == 1
        assert all(i["project_id"] == _s["pid_a"] for i in ra["recent"])
        assert all(i["project_id"] == _s["pid_b"] for i in rb["recent"])

    def test_unauthenticated_rejected(self, module_client: TestClient):
        module_client.post("/api/auth/logout")
        r = module_client.get(f"/api/projects/{_s['pid_a']}/ext/ioc-tracker/iocs")
        assert r.status_code == 401
        _login_admin(module_client)
