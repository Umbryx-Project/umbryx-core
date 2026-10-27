"""C2 router path/authorization model (security test 2026-09-02, finding 5).

Product-owner decision (2026-09-02): project operators CAN use project-
scoped C2 endpoints (sessions, host-actions, execute…) when the integration
is bound to their project — the misleading /api/admin/ prefix was renamed to
/api/c2/. Integration management (create/patch/delete) stays admin-only.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
OP_PASS = "C2OpPass1234!"

_s: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient, module_db: Session):
    c = module_client
    c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    c.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})

    r = c.post("/api/projects", json={"name": "C2 Path Test", "added": "2025-01-01T00:00:00Z", "status": "active"})
    _s["pid"] = r.json()["id"]

    r = c.post("/api/admin/users", json={"username": "c2_operator", "password": OP_PASS, "role": "user"})
    _s["op_uid"] = r.json()["id"]
    c.post(f"/api/projects/{_s['pid']}/members", json={"user_id": _s["op_uid"], "role": "operator"})

    # Enabled integration bound to the project, stored the production way.
    # c2_integrations is a single shared GlobalSetting row keyed by "key" —
    # other test modules (test_c2_ops.py, test_c2_ops_multi.py,
    # test_c2_push_registration.py) write to the same row in the same
    # in-memory sqlite DB for the whole pytest session, so this must
    # append to whatever's already there rather than unconditionally
    # INSERTing, or it collides with a UNIQUE constraint on .key whenever
    # one of those modules already ran first (2026-09-16 CI failure).
    from app import models

    integration = {
        "id": "c2path1",
        "type": "adaptix",
        "name": "path-test",
        "url": "https://adaptix.internal:8443",
        "enabled": True,
        "project_ids": [_s["pid"]],
    }
    row = module_db.query(models.GlobalSetting).filter(models.GlobalSetting.key == "c2_integrations").first()
    if row:
        from sqlalchemy.orm.attributes import flag_modified

        value = row.value if isinstance(row.value, list) else []
        value.append(integration)
        row.value = value
        flag_modified(row, "value")
    else:
        module_db.add(models.GlobalSetting(key="c2_integrations", value=[integration]))
    module_db.commit()
    # The router's _require_c2() gate 404s when the c2_integration plugin is
    # disabled — keep it satisfied for every request in this module.
    from app.plugins.registry import registry

    class _Gate:
        enabled = True

    _orig_get = registry.get
    registry.get = lambda key: _Gate() if key == "c2_integration" else _orig_get(key)
    yield
    registry.get = _orig_get


class TestC2PathModel:
    def test_old_admin_path_gone(self, module_client: TestClient):
        module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
        r = module_client.get("/api/admin/c2")
        assert r.status_code == 404

    def test_operator_sees_project_scoped_endpoints(self, module_client: TestClient):
        module_client.post("/api/auth/login", json={"username": "c2_operator", "password": OP_PASS})
        r = module_client.get(f"/api/c2/for-project/{_s['pid']}")
        assert r.status_code == 200, r.text
        integrations = r.json()
        assert any(i.get("id") == "c2path1" for i in integrations)

        # sessions listing reaches out to the teamserver; with no live C2 the
        # endpoint must degrade gracefully, not 401/403 — accept connection
        # errors surfaced as 502/empty but NOT authorization failures
        r = module_client.get(f"/api/c2/sessions/{_s['pid']}")
        assert r.status_code != 403
        assert r.status_code != 401

    def test_operator_cannot_mutate_integrations(self, module_client: TestClient):
        module_client.post("/api/auth/login", json={"username": "c2_operator", "password": OP_PASS})
        r = module_client.delete("/api/c2/c2path1")
        assert r.status_code == 403
        r = module_client.patch("/api/c2/c2path1", json={"name": "hijack"})
        assert r.status_code == 403

    def test_admin_still_manages_integrations(self, module_client: TestClient):
        module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
        r = module_client.get("/api/c2")
        assert r.status_code == 200
        ids = [i.get("id") for i in r.json()]
        assert "c2path1" in ids
