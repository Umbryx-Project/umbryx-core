"""
Phase 1.5 — Integration tests for system metrics/workers/infra-health endpoints.
"""
import pytest
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
USER_PASS = "MetricsPass1234!"

_s: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    c = module_client
    c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = c.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200

    r = c.post("/api/admin/users", json={"username": "metrics_platadmin", "password": USER_PASS, "role": "platform_admin"})
    assert r.status_code in (200, 201)
    _s["platadmin_uid"] = r.json()["id"]

    r = c.post("/api/admin/users", json={"username": "metrics_regular", "password": USER_PASS, "role": "user"})
    assert r.status_code in (200, 201)
    _s["regular_uid"] = r.json()["id"]

    r = c.post("/api/projects", json={"name": "Metrics Test", "added": "2025-01-01T00:00:00Z", "status": "active"})
    _s["pid"] = r.json()["id"]

    c.post("/api/hosts", json={"pid": _s["pid"], "ip": "10.0.0.1"})
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


class TestMetricsEndpoint:
    def test_admin_can_access_metrics(self, module_client: TestClient):
        r = module_client.get("/api/system/metrics")
        assert r.status_code == 200
        data = r.json()
        assert "job_status_counts" in data
        assert "total_projects" in data
        assert data["total_projects"] >= 1
        assert "total_users" in data
        assert data["total_users"] >= 1

    def test_platadmin_can_access_metrics(self, module_client: TestClient):
        _as(module_client, "metrics_platadmin")
        r = module_client.get("/api/system/metrics")
        assert r.status_code == 200
        _as_admin(module_client)

    def test_regular_blocked_from_metrics(self, module_client: TestClient):
        _as(module_client, "metrics_regular")
        r = module_client.get("/api/system/metrics")
        assert r.status_code == 403
        _as_admin(module_client)


class TestWorkersEndpoint:
    def test_admin_can_access_workers(self, module_client: TestClient):
        r = module_client.get("/api/system/workers")
        assert r.status_code == 200
        data = r.json()
        assert "active_workers" in data
        assert "workers" in data

    def test_platadmin_can_access_workers(self, module_client: TestClient):
        _as(module_client, "metrics_platadmin")
        r = module_client.get("/api/system/workers")
        assert r.status_code == 200
        _as_admin(module_client)

    def test_regular_blocked_from_workers(self, module_client: TestClient):
        _as(module_client, "metrics_regular")
        r = module_client.get("/api/system/workers")
        assert r.status_code == 403
        _as_admin(module_client)


class TestInfraHealthEndpoint:
    def test_admin_can_access_infra(self, module_client: TestClient):
        r = module_client.get("/api/system/infra-health")
        assert r.status_code == 200
        data = r.json()
        assert "project_status_counts" in data
        assert "member_role_counts" in data
        assert "system_log_count" in data

    def test_platadmin_can_access_infra(self, module_client: TestClient):
        _as(module_client, "metrics_platadmin")
        r = module_client.get("/api/system/infra-health")
        assert r.status_code == 200
        _as_admin(module_client)

    def test_regular_blocked_from_infra(self, module_client: TestClient):
        _as(module_client, "metrics_regular")
        r = module_client.get("/api/system/infra-health")
        assert r.status_code == 403
        _as_admin(module_client)
