"""The Community/Enterprise seam (core/editions.py, docs/modules/EDITIONS.md).

The test suite runs against the Enterprise tree, so "does CE work" cannot
be answered by just running it — the Community build is simulated here by
forcing the detection flag, which is the one thing the whole seam depends
on.
"""
import pytest
from fastapi.testclient import TestClient

from ._license_test_utils import license_ee, reset_instance_license

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
_s: dict = {}


@pytest.fixture
def as_community(monkeypatch):
    """Pretend app.ee is absent, the way a CE build has it."""
    from app.core import editions

    editions.reset_cache()
    monkeypatch.setattr(editions, "_available", False)
    yield
    editions.reset_cache()


@pytest.fixture
def as_enterprise(monkeypatch):
    from app.core import editions

    editions.reset_cache()
    monkeypatch.setattr(editions, "_available", True)
    yield
    editions.reset_cache()


class TestEditionDetection:
    def test_edition_follows_whether_the_package_is_importable(self):
        """The reported edition is not configuration — it is whether the
        Enterprise package is actually in this build."""
        import importlib.util

        from app.core.editions import edition, ee_available

        present = importlib.util.find_spec("app.ee") is not None
        assert ee_available() is present
        assert edition() == ("ee" if present else "ce")

    def test_community_reports_ce(self, as_community):
        from app.core.editions import edition

        assert edition() == "ce"

    def test_enterprise_reports_ee(self, as_enterprise):
        from app.core.editions import edition

        assert edition() == "ee"

    def test_detection_is_cached_and_resettable(self, monkeypatch):
        from app.core import editions

        editions.reset_cache()
        first = editions.ee_available()
        calls = []

        def counting_find_spec(name):
            calls.append(name)
            return None

        monkeypatch.setattr(editions.importlib.util, "find_spec", counting_find_spec)
        assert editions.ee_available() is first
        assert calls == [], "a cached answer must not re-walk the filesystem"

        editions.reset_cache()
        assert editions.ee_available() is False
        assert calls == [editions.EE_PACKAGE]


class TestOptionalImport:
    def test_ee_import_returns_none_in_community(self, as_community):
        from app.core.editions import ee_import

        assert ee_import("infra") is None

    def test_ee_routers_is_empty_in_community(self, as_community):
        from app.core.editions import ee_routers

        assert ee_routers() == []

    def test_missing_ee_module_in_enterprise_build_propagates(self, as_enterprise):
        """A genuine error inside the Enterprise package must not be
        swallowed into a Community-shaped install — that would ship a
        silently degraded EE."""
        from app.core.editions import ee_import

        with pytest.raises(ModuleNotFoundError):
            ee_import("definitely_not_a_module")


class TestRoutingTolerance:
    """routing.py mounts EE routers unconditionally; the seam decides
    whether there are any. Asserted by calling the endpoints rather than
    counting app.routes — FastAPI expands an included router lazily, so the
    route objects are not there to count until the app is actually served.
    """

    def _probe_router(self):
        from fastapi import APIRouter

        router = APIRouter()

        @router.get("/api/ee-probe")
        def _probe():
            return {"ok": True}

        return router

    def test_community_build_mounts_nothing(self, as_community):
        from fastapi import FastAPI

        from app.routing import _register_ee

        # No stubbing here on purpose: the guard inside ee_import is exactly
        # what is under test, so patching it would test the patch.
        app = FastAPI()
        _register_ee(app)
        assert TestClient(app).get("/api/ee-probe").status_code == 404

    def test_enterprise_build_mounts_the_packages_routers(self, as_enterprise, monkeypatch):
        import types

        from fastapi import FastAPI

        from app.core import editions
        from app.routing import _register_ee

        fake = types.SimpleNamespace(ROUTERS=[self._probe_router()])
        monkeypatch.setattr(editions, "ee_import", lambda name: fake if name == "routers" else None)

        app = FastAPI()
        _register_ee(app)
        r = TestClient(app).get("/api/ee-probe")
        assert r.status_code == 200, r.text
        assert r.json() == {"ok": True}


class TestEditionEndpoint:
    @pytest.fixture(scope="class", autouse=True)
    def _bootstrap(self, module_client: TestClient, module_db):
        c = module_client
        reset_instance_license(module_db)
        c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
        assert c.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS}).status_code == 200
        yield
        reset_instance_license(module_db)

    def test_reports_edition_and_unlicensed_entitlement(self, module_client: TestClient):
        r = module_client.get("/api/system/edition")
        assert r.status_code == 200, r.text
        data = r.json()
        assert data["edition"] in ("ce", "ee")
        assert data["tier"] == "free"
        assert data["features"] == []
        # Free is Community Edition: no deployment allowance at all.
        assert data["limits"]["max_infra_instances"] == 0
        assert data["limits"]["max_workstations"] == 0

    def test_reports_license_entitlement_when_licensed(
        self, module_client: TestClient, module_db, monkeypatch
    ):
        undo = license_ee(module_client, module_db)
        try:
            data = module_client.get("/api/system/edition").json()
            assert data["tier"] == "enterprise"
            assert "infra_lifecycle" in data["features"]
            assert data["limits"]["max_infra_instances"] == -1
        finally:
            undo()

    def test_requires_authentication(self, module_client: TestClient):
        module_client.post("/api/auth/logout")
        try:
            assert module_client.get("/api/system/edition").status_code in (401, 403)
        finally:
            module_client.post(
                "/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS}
            )


class TestCommunityWorkstations:
    """A Community build answers 404 on provisioning and keeps the
    operator's own machines working.

    The instance is licensed on purpose. The license gate (402) runs as a
    route dependency, i.e. before the handler, so an unlicensed instance
    would answer 402 and hide the 404 entirely. Licensing isolates the
    other axis: this is what a customer with a valid Enterprise license
    running the Community artifact sees — the capability is paid for but
    simply is not in this build.
    """

    @pytest.fixture(scope="class", autouse=True)
    def _bootstrap(self, module_client: TestClient, module_db):
        c = module_client
        c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
        c.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
        undo = license_ee(c, module_db)
        r = c.post(
            "/api/projects",
            json={"name": "Edition WS", "added": "2025-01-01T00:00:00Z", "status": "active"},
        )
        _s["pid"] = r.json()["id"]

        # A real workstation row, so POST /{id}/provision reaches the seam
        # instead of 404ing earlier on an unknown id — the status would be
        # the same and the test would prove nothing.
        from app import models
        from app.core.utils import new_id, ts_now

        ws = models.OperatorWorkstation(
            id=new_id("ws"),
            project_id=_s["pid"],
            name="edition-probe",
            provider="hetzner",
            status="planned",
            created_at=ts_now(),
        )
        module_db.add(ws)
        module_db.commit()
        _s["probe_ws_id"] = ws.id

        yield
        undo()

    PROVISIONING = [
        ("post", "/api/workstations", {"project_id": None, "template_id": "t", "name": "x"}),
        ("post", "/api/workstations/{ws}/provision", None),
        ("post", "/api/workstations/pool", {"infra_provider_id": "p", "name": "n"}),
        ("get", "/api/workstations/providers", None),
        ("get", "/api/workstations/pool/providers", None),
    ]

    @pytest.mark.parametrize(("method", "path", "body"), PROVISIONING)
    def test_provisioning_is_absent(self, module_client, as_community, method, path, body):
        if body is not None and "project_id" in body:
            body = {**body, "project_id": _s["pid"]}
        path = path.format(ws=_s["probe_ws_id"])
        r = getattr(module_client, method)(path, json=body) if body else getattr(module_client, method)(path)
        assert r.status_code == 404, f"{path}: {r.status_code} {r.text}"
        assert "Community Edition" in r.json()["detail"]

    def test_template_list_reads_empty_instead_of_failing(self, module_client, as_community):
        """A read stays a read: there are no provisioning templates in this
        edition, which is an empty list, not an error."""
        r = module_client.get("/api/workstations/templates")
        assert r.status_code == 200, r.text
        assert isinstance(r.json(), list)

    def test_registering_an_existing_machine_still_works(self, module_client, as_community):
        r = module_client.post(
            "/api/workstations/pool/ignored/register-manual",
            json={
                "name": "ce-own-box",
                "access_address": "198.51.100.77",
                "auth": {"type": "password", "secret": "s3cret"},
            },
        )
        assert r.status_code == 201, r.text
        _s["ce_ws_id"] = r.json()["id"]

    def test_pool_listing_still_works(self, module_client, as_community):
        r = module_client.get("/api/workstations/pool")
        assert r.status_code == 200, r.text

    def test_own_machine_can_still_be_force_deleted(self, module_client, as_community):
        """The absence of the provisioning package must not be filed as a
        teardown failure — that would keep the row and leave the admin
        unable to delete a machine this build never created."""
        ws_id = _s.get("ce_ws_id")
        assert ws_id, "registration test must run first"
        r = module_client.delete(f"/api/workstations/{ws_id}/force")
        assert r.status_code != 500, r.text
        assert r.status_code in (200, 204), r.text


class TestCommunityProjectClosure:
    """Closing a project in a build without the deployment package must not
    file the absence as an infrastructure failure.

    The teardown block in core/closure.py is wrapped in a broad `except`
    that turns anything into a warning on the decommission report. A
    Community install has no stacks to tear down, so a warning there would
    appear on every closure — in a compliance artifact, which is the worst
    place for a misleading line.
    """

    @pytest.fixture
    def project(self, module_client: TestClient):
        module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
        module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
        r = module_client.post(
            "/api/projects",
            json={"name": "Closure CE", "added": "2025-01-01T00:00:00Z", "status": "active"},
        )
        assert r.status_code in (200, 201), r.text
        return r.json()["id"]

    def test_no_infrastructure_warning_without_the_package(
        self, module_db, project, as_community
    ):
        import asyncio

        from app.core.closure import close_project

        report = asyncio.run(close_project(project, "tester", module_db))
        warnings = report.warnings if isinstance(report.warnings, list) else []
        infra = [w for w in warnings if "Infrastructure" in str(w)]
        assert infra == [], f"closure reported infrastructure trouble in Community: {infra}"
