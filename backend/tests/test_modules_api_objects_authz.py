"""Regression tests for the modules_api universal object CRUD authz fix.

Security audit finding (2026-08-29, P0-3): PATCH/DELETE/GET/POST/relations
endpoints under /api/modules/objects had no project-membership check at all,
so any authenticated user could read/modify/delete any project's module
objects. These tests pin the fix: project-scoped objects require membership,
global (project_id=None) objects require admin for mutation.
"""

import pytest
from fastapi.testclient import TestClient

from app.core.modules.manifest import ObjectTypeSchema
from app.core.modules.object_types import obj_type_registry

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
OUTSIDER_PASS = "OutsiderPass1234!"

_s: dict = {}


def _login(c: TestClient, username: str, password: str):
    r = c.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, f"login failed for {username}: {r.text}"


def _logout(c: TestClient):
    c.post("/api/auth/logout")


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    obj_type_registry.register(
        "test-authz-module",
        ObjectTypeSchema(type="authz_test_obj", name="Authz Test Object"),
    )
    c = module_client
    c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    _login(c, ADMIN, ADMIN_PASS)

    r = c.post(
        "/api/projects",
        json={"name": "ModulesAuthzTest", "added": "2025-01-01T00:00:00Z", "status": "active"},
    )
    assert r.status_code == 201, r.text
    _s["pid"] = r.json()["id"]

    r = c.post(
        "/api/admin/users",
        json={"username": "modules_outsider", "password": OUTSIDER_PASS, "role": "user"},
    )
    assert r.status_code in (200, 201), r.text

    r = c.post(
        "/api/modules/objects",
        json={"type": "authz_test_obj", "project_id": _s["pid"], "name": "scoped"},
    )
    assert r.status_code == 200, r.text
    _s["scoped_obj_id"] = r.json()["id"]

    r = c.post("/api/modules/objects", json={"type": "authz_test_obj", "name": "global"})
    assert r.status_code == 200, r.text
    _s["global_obj_id"] = r.json()["id"]

    _logout(c)
    yield
    obj_type_registry.unregister_module("test-authz-module")


class TestProjectScopedObjectAuthz:
    def test_outsider_cannot_read_scoped_object(self, module_client: TestClient):
        _login(module_client, "modules_outsider", OUTSIDER_PASS)
        r = module_client.get(f"/api/modules/objects/{_s['scoped_obj_id']}")
        assert r.status_code in (403, 404)
        _logout(module_client)

    def test_outsider_cannot_update_scoped_object(self, module_client: TestClient):
        _login(module_client, "modules_outsider", OUTSIDER_PASS)
        r = module_client.patch(
            f"/api/modules/objects/{_s['scoped_obj_id']}", json={"name": "pwned"}
        )
        assert r.status_code in (403, 404)
        _logout(module_client)

    def test_outsider_cannot_delete_scoped_object(self, module_client: TestClient):
        _login(module_client, "modules_outsider", OUTSIDER_PASS)
        r = module_client.delete(f"/api/modules/objects/{_s['scoped_obj_id']}")
        assert r.status_code in (403, 404)
        _logout(module_client)

    def test_outsider_cannot_create_in_foreign_project(self, module_client: TestClient):
        _login(module_client, "modules_outsider", OUTSIDER_PASS)
        r = module_client.post(
            "/api/modules/objects",
            json={"type": "authz_test_obj", "project_id": _s["pid"], "name": "sneaky"},
        )
        assert r.status_code in (403, 404)
        _logout(module_client)

    def test_outsider_list_excludes_foreign_project(self, module_client: TestClient):
        _login(module_client, "modules_outsider", OUTSIDER_PASS)
        r = module_client.get("/api/modules/objects", params={"type": "authz_test_obj"})
        assert r.status_code == 200
        ids = [o["id"] for o in r.json()["items"]]
        assert _s["scoped_obj_id"] not in ids
        _logout(module_client)

    def test_admin_can_still_read_scoped_object(self, module_client: TestClient):
        _login(module_client, ADMIN, ADMIN_PASS)
        r = module_client.get(f"/api/modules/objects/{_s['scoped_obj_id']}")
        assert r.status_code == 200
        _logout(module_client)


class TestGlobalObjectAuthz:
    def test_outsider_cannot_mutate_global_object(self, module_client: TestClient):
        _login(module_client, "modules_outsider", OUTSIDER_PASS)
        r = module_client.patch(
            f"/api/modules/objects/{_s['global_obj_id']}", json={"name": "pwned"}
        )
        assert r.status_code == 403
        _logout(module_client)

    def test_outsider_can_read_global_object(self, module_client: TestClient):
        _login(module_client, "modules_outsider", OUTSIDER_PASS)
        r = module_client.get(f"/api/modules/objects/{_s['global_obj_id']}")
        assert r.status_code == 200
        _logout(module_client)

    def test_admin_can_mutate_global_object(self, module_client: TestClient):
        _login(module_client, ADMIN, ADMIN_PASS)
        r = module_client.patch(
            f"/api/modules/objects/{_s['global_obj_id']}", json={"name": "renamed"}
        )
        assert r.status_code == 200
        assert r.json()["name"] == "renamed"
        _logout(module_client)
