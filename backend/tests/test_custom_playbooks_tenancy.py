"""Custom playbook tenant scoping (audit 2026-08-31, finding 3.3).

Scoping target: organization — an implementer's decision from code
analysis, confirmed by the product owner post-hoc on 2026-09-01. Org-scoped playbooks
are visible to the org's members; personal ones (org_id NULL) to their
creator; platform admins see everything. Running a playbook the caller
can't see must 404 — not leak it via execution.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.plugins.loader import _register_builtin_modules

_register_builtin_modules()  # populate the connector registry like sibling playbook tests

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
USER_PASS = "PbPass1234!secure"

_s: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient, module_db: Session):
    c = module_client
    c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    c.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})

    def _user(name):
        r = c.post(
            "/api/admin/users",
            json={"username": name, "password": USER_PASS, "role": "user"},
        )
        assert r.status_code in (200, 201), r.text
        return r.json()["id"]

    _s["ua"] = _user("pb_org_a")
    _s["ub"] = _user("pb_org_b")
    _s["uc"] = _user("pb_no_org")

    r = c.post("/api/orgs", json={"name": "PB Org A", "slug": "pb-org-a"})
    assert r.status_code in (200, 201), r.text
    _s["org_a"] = r.json()["id"]
    r = c.post("/api/orgs", json={"name": "PB Org B", "slug": "pb-org-b"})
    assert r.status_code in (200, 201), r.text
    _s["org_b"] = r.json()["id"]

    c.post(f"/api/orgs/{_s['org_a']}/members", json={"user_id": _s["ua"], "role": "operator"})
    c.post(f"/api/orgs/{_s['org_b']}/members", json={"user_id": _s["ub"], "role": "operator"})

    # login as org-a user, create an org-scoped and a personal playbook
    c.post("/api/auth/logout")
    c.post("/api/auth/login", json={"username": "pb_org_a", "password": USER_PASS})
    r = c.post(
        "/api/playbooks/custom",
        json={"title": "Org A playbook", "org_id": _s["org_a"], "steps": [{"title": "s1", "connector_key": "nmap", "operation": "scan"}]},
    )
    assert r.status_code == 201, r.text
    _s["pb_org"] = r.json()["id"]
    r = c.post("/api/playbooks/custom", json={"title": "Personal A", "steps": [{"title": "s1", "connector_key": "nmap", "operation": "scan"}]})
    assert r.status_code == 201, r.text
    _s["pb_personal"] = r.json()["id"]

    # org-b user creates their own
    c.post("/api/auth/logout")
    c.post("/api/auth/login", json={"username": "pb_org_b", "password": USER_PASS})
    r = c.post(
        "/api/playbooks/custom",
        json={"title": "Org B playbook", "org_id": _s["org_b"], "steps": [{"title": "s1", "connector_key": "nmap", "operation": "scan"}]},
    )
    assert r.status_code == 201, r.text
    _s["pb_b"] = r.json()["id"]
    c.post("/api/auth/logout")
    yield


def _login(c: TestClient, who: str):
    c.post("/api/auth/logout")
    c.post("/api/auth/login", json={"username": who, "password": USER_PASS})


class TestCustomPlaybookTenancy:
    def test_org_member_sees_own_org_and_personal_only(self, module_client: TestClient):
        _login(module_client, "pb_org_a")
        r = module_client.get("/api/playbooks")
        assert r.status_code == 200
        ids = [p["id"] for p in r.json()["playbooks"] if p.get("source") == "custom"]
        assert _s["pb_org"] in ids
        assert _s["pb_personal"] in ids
        assert _s["pb_b"] not in ids  # other org's playbook invisible

    def test_other_org_member_cannot_see(self, module_client: TestClient):
        _login(module_client, "pb_org_b")
        r = module_client.get("/api/playbooks")
        ids = [p["id"] for p in r.json()["playbooks"] if p.get("source") == "custom"]
        assert _s["pb_b"] in ids
        assert _s["pb_org"] not in ids
        assert _s["pb_personal"] not in ids  # someone else's personal

    def test_orgless_user_sees_nothing_of_others(self, module_client: TestClient):
        _login(module_client, "pb_no_org")
        r = module_client.get("/api/playbooks")
        ids = [p["id"] for p in r.json()["playbooks"] if p.get("source") == "custom"]
        assert ids == []

    def test_platform_admin_sees_all(self, module_client: TestClient):
        module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
        r = module_client.get("/api/playbooks")
        ids = [p["id"] for p in r.json()["playbooks"] if p.get("source") == "custom"]
        assert {_s["pb_org"], _s["pb_personal"], _s["pb_b"]} <= set(ids)

    def test_create_in_foreign_org_rejected(self, module_client: TestClient):
        _login(module_client, "pb_org_a")
        r = module_client.post(
            "/api/playbooks/custom",
            json={"title": "Sneaky", "org_id": _s["org_b"], "steps": [{"title": "s1", "connector_key": "nmap", "operation": "scan"}]},
        )
        assert r.status_code == 403

    def test_update_delete_by_outsider_404(self, module_client: TestClient):
        _login(module_client, "pb_org_b")
        r = module_client.patch(
            f"/api/playbooks/custom/{_s['pb_org']}", json={"title": "hijack"}
        )
        assert r.status_code == 404
        r = module_client.delete(f"/api/playbooks/custom/{_s['pb_org']}")
        assert r.status_code == 404

    def test_export_scoped(self, module_client: TestClient):
        _login(module_client, "pb_org_a")
        r = module_client.get("/api/playbooks/custom/export")
        assert r.status_code == 200
        titles = [p["title"] for p in r.json()["playbooks"]]
        assert "Org A playbook" in titles
        assert "Org B playbook" not in titles
