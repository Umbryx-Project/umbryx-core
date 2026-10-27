"""Scope extension request endpoint (ROE alert follow-up action).

Audit 2026-08-31 follow-up: a scope-blocked job must offer the operator an
actionable path — request an extension — which notifies project admins
instead of letting the operator widen the engagement boundary unilaterally.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
OP_PASS = "ExtPass1234!ok"

_s: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    c = module_client
    c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    c.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    r = c.post("/api/projects", json={"name": "Scope Ext Test", "added": "2025-01-01T00:00:00Z", "status": "active"})
    _s["pid"] = r.json()["id"]
    r = c.post("/api/admin/users", json={"username": "ext_operator", "password": OP_PASS, "role": "user"})
    _s["op_uid"] = r.json()["id"]
    c.post(f"/api/projects/{_s['pid']}/members", json={"user_id": _s["op_uid"], "role": "operator"})
    yield
    c.post("/api/auth/logout")


class TestScopeExtensionRequest:
    def test_operator_can_request(self, module_client: TestClient, module_db: Session):
        from app import models

        module_client.post("/api/auth/login", json={"username": "ext_operator", "password": OP_PASS})
        r = module_client.post(
            "/api/scopes/extension-request",
            json={"pid": _s["pid"], "value": "10.99.0.0/24", "reason": "client approved new subnet", "blocked_job_id": "job_x"},
        )
        assert r.status_code == 201, r.text
        assert r.json()["ok"] is True
        assert r.json()["notified"] >= 1

        # Notification must reach someone who can change the scope
        from app.core.permissions import get_permissions_for_role

        members = module_db.query(models.ProjectMember).filter(
            models.ProjectMember.project_id == _s["pid"], models.ProjectMember.is_active
        ).all()
        admin_uids = {m.user_id for m in members if "scopes.update" in get_permissions_for_role(m.role)}
        notified = (
            module_db.query(models.Notification)
            .filter(models.Notification.project_id == _s["pid"])
            .all()
        )
        notified_uids = {n.user_id for n in notified}
        assert admin_uids & notified_uids
        assert any("10.99.0.0/24" in (n.body or "") for n in notified)

    def test_validation(self, module_client: TestClient):
        r = module_client.post("/api/scopes/extension-request", json={"pid": "", "value": ""})
        assert r.status_code == 400

    def test_outsider_rejected(self, module_client: TestClient, module_db: Session):
        module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
        module_client.post(
            "/api/admin/users",
            json={"username": "ext_outsider", "password": OP_PASS, "role": "user"},
        )
        module_client.post("/api/auth/logout")
        module_client.post("/api/auth/login", json={"username": "ext_outsider", "password": OP_PASS})
        r = module_client.post(
            "/api/scopes/extension-request",
            json={"pid": _s["pid"], "value": "10.0.0.0/8"},
        )
        assert r.status_code == 404  # not a member
