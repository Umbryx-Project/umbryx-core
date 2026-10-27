"""
Phase 4 — Project Closure & Decommission tests.
"""
import pytest
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
_s: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    c = module_client
    c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    c.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})

    r = c.post("/api/projects", json={"name": "Closure Test", "added": "2025-01-01T00:00:00Z", "status": "active"})
    _s["pid"] = r.json()["id"]

    c.post("/api/creds", json={
        "pid": _s["pid"],
        "username": "closure-user",
        "secret": "closure-secret",
        "type": "plain",
    })

    c.get("/api/infra/templates")
    c.post("/api/infra/instances", json={
        "project_id": _s["pid"],
        "template_id": "builtin-tooling-kali",
        "name": "Closure Infra",
    })

    yield
    c.post("/api/auth/logout")


class TestClosurePreview:
    def test_preview_active_project(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_s['pid']}/closure-preview")
        assert r.status_code == 200
        data = r.json()
        assert data["can_close"] is True
        assert data["project_status"] == "active"

    def test_preview_missing_project(self, module_client: TestClient):
        r = module_client.get("/api/projects/nonexistent/closure-preview")
        assert r.status_code == 404


class TestProjectClose:
    def test_close_project(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_s['pid']}/close")
        assert r.status_code == 200
        data = r.json()
        assert data["final_status"] in ("completed", "completed_with_warnings")
        assert data["project_id"] == _s["pid"]
        assert data["closure_completed_at"] is not None
        assert len(data["members_deactivated"]) >= 1
        _s["report_id"] = data["id"]

    def test_project_status_is_closed(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_s['pid']}/closure-preview")
        assert r.status_code == 200
        assert r.json()["project_status"] == "closed"

    def test_cannot_close_again(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_s['pid']}/close")
        assert r.status_code == 400

    def test_decommission_report(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_s['pid']}/decommission-report")
        assert r.status_code == 200
        data = r.json()
        assert data["id"] == _s["report_id"]
        assert "infra_destroyed" in data
        assert "secrets_revoked" in data

    def test_report_not_found_for_other_project(self, module_client: TestClient):
        r = module_client.post("/api/projects", json={"name": "Other Project", "added": "2025-01-01T00:00:00Z", "status": "active"})
        other_pid = r.json()["id"]
        resp = module_client.get(f"/api/projects/{other_pid}/decommission-report")
        assert resp.status_code == 404


class TestProjectArchive:
    def test_archive_closed_project(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_s['pid']}/archive")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "archived"
        assert data["archived_at"] is not None

    def test_cannot_archive_twice(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_s['pid']}/archive")
        assert r.status_code == 400


class TestClosureUnit:
    def test_can_transition(self):
        from app.core.closure import can_transition
        assert can_transition("active", "closing") is True
        assert can_transition("closing", "closed") is True
        assert can_transition("closed", "archived") is True
        assert can_transition("active", "archived") is False
        assert can_transition("closed", "closing") is False
        assert can_transition("draft", "active") is True
