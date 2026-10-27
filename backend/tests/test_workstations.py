"""
Phase 5 — Operator Workstations tests.
"""
import pytest
from fastapi.testclient import TestClient

from ._license_test_utils import license_ee

# Enterprise-only: the module's bootstrap provisions a workstation and
# every class here drives provisioning, templates or teardown of a
# machine Umbryx created. Community registers machines the operator
# already owns — covered by test_workstation_pool.py. Skipped rather
# than failed; see conftest.py::pytest_collection_modifyitems.
pytestmark = pytest.mark.ee

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
_s: dict = {}


def _set_ws_status(ws_id, status):
    from app import database, models
    db = database.SessionLocal()
    ws = db.query(models.OperatorWorkstation).filter(
        models.OperatorWorkstation.id == ws_id
    ).first()
    if ws:
        ws.status = status
        db.commit()
    db.close()


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient, module_db):
    c = module_client
    c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    c.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    # Provisioning workstations is Enterprise-only (docs/modules/EDITIONS.md)
    # and this whole module provisions them, so the instance is licensed.
    undo = license_ee(c, module_db)
    r = c.post("/api/projects", json={"name": "WS Test", "added": "2025-01-01T00:00:00Z", "status": "active"})
    _s["pid"] = r.json()["id"]
    c.get("/api/workstations/templates")
    r = c.post("/api/workstations", json={
        "project_id": _s["pid"],
        "template_id": "builtin-kali-minimal",
        "name": "ws-provision-test",
    })
    _s["ws_id"] = r.json()["id"]
    yield
    undo()
    c.post("/api/auth/logout")


class TestWorkstationTemplates:
    def test_list_includes_builtins(self, module_client: TestClient):
        r = module_client.get("/api/workstations/templates")
        assert r.status_code == 200
        templates = r.json()
        ids = [t["id"] for t in templates]
        assert "builtin-kali-minimal" in ids
        assert "builtin-kali-web" in ids
        assert "builtin-kali-ad" in ids
        assert "builtin-ubuntu-tools" in ids

    def test_builtin_has_image_spec(self, module_client: TestClient):
        r = module_client.get("/api/workstations/templates")
        templates = r.json()
        kali = next(t for t in templates if t["id"] == "builtin-kali-minimal")
        assert "image" in kali["spec"]
        assert "kalilinux" in kali["spec"]["image"]

    def test_create_custom_template(self, module_client: TestClient):
        r = module_client.post("/api/workstations/templates", json={
            "name": "Custom Pentest Box",
            "kind": "docker",
            "spec": {"image": "parrotsec/security:latest", "ports": ["2222:22"]},
        })
        assert r.status_code == 200
        data = r.json()
        assert data["name"] == "Custom Pentest Box"
        assert data["is_builtin"] is False
        _s["custom_tpl"] = data["id"]

    def test_delete_builtin_forbidden(self, module_client: TestClient):
        r = module_client.delete("/api/workstations/templates/builtin-kali-minimal")
        assert r.status_code == 400

    def test_delete_custom_template(self, module_client: TestClient):
        r = module_client.delete(f"/api/workstations/templates/{_s['custom_tpl']}")
        assert r.status_code == 200


class TestWorkstationCRUD:
    def test_create_workstation(self, module_client: TestClient):
        r = module_client.post("/api/workstations", json={
            "project_id": _s["pid"],
            "template_id": "builtin-kali-minimal",
            "name": "ws-test-box",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "planned"
        assert data["name"] == "ws-test-box"
        _s["ws_id"] = data["id"]

    def test_list_workstations(self, module_client: TestClient):
        r = module_client.get("/api/workstations", params={"project_id": _s["pid"]})
        assert r.status_code == 200
        assert any(w["id"] == _s["ws_id"] for w in r.json())

    def test_get_workstation(self, module_client: TestClient):
        r = module_client.get(f"/api/workstations/{_s['ws_id']}")
        assert r.status_code == 200
        assert r.json()["id"] == _s["ws_id"]

    def test_create_missing_fields_400(self, module_client: TestClient):
        r = module_client.post("/api/workstations", json={"name": "bad"})
        assert r.status_code == 400

    def test_create_bad_template_404(self, module_client: TestClient):
        r = module_client.post("/api/workstations", json={
            "project_id": _s["pid"],
            "template_id": "nonexistent",
        })
        assert r.status_code == 404


class TestWorkstationProvisionDestroy:
    def test_provision_docker_not_available(self, module_client: TestClient):
        r = module_client.post(f"/api/workstations/{_s['ws_id']}/provision")
        assert r.status_code == 202
        assert r.json()["status"] == "provisioning"
        _set_ws_status(_s["ws_id"], "failed")

    def test_re_provision(self, module_client: TestClient):
        r = module_client.post(f"/api/workstations/{_s['ws_id']}/provision")
        assert r.status_code == 202
        _set_ws_status(_s["ws_id"], "failed")

    def test_destroy_workstation(self, module_client: TestClient):
        r = module_client.post(f"/api/workstations/{_s['ws_id']}/destroy")
        assert r.status_code == 202
        assert r.json()["status"] == "destroying"
        _set_ws_status(_s["ws_id"], "destroyed")

    def test_destroy_already_destroyed_400(self, module_client: TestClient):
        r = module_client.post(f"/api/workstations/{_s['ws_id']}/destroy")
        assert r.status_code == 400

    def test_delete_destroyed_workstation(self, module_client: TestClient):
        r = module_client.delete(f"/api/workstations/{_s['ws_id']}")
        assert r.status_code == 200


class TestInfraEvents:
    def test_post_event(self, module_client: TestClient):
        r = module_client.post("/api/workstations", json={
            "project_id": _s["pid"],
            "template_id": "builtin-kali-minimal",
            "name": "event-test-ws",
        })
        ws_id = r.json()["id"]

        r = module_client.post(f"/api/workstations/{ws_id}/events", json={
            "event_type": "session_start",
            "payload": {"user": "admin", "method": "ssh"},
        })
        assert r.status_code == 200
        assert r.json()["event_type"] == "session_start"

        r = module_client.get(f"/api/workstations/{ws_id}/events")
        assert r.status_code == 200
        events = r.json()
        assert len(events) >= 1
        assert events[0]["event_type"] == "session_start"

        module_client.delete(f"/api/workstations/{ws_id}")


# ════════ force-delete teardown honesty (audit 2026-08-31, finding 2.3.3) ════════


class TestWorkstationsForceDeleteTeardown:
    """A failed real teardown must keep the DB record (marked failed, with
    the reason) instead of silently dropping it and orphaning the resource."""

    def _make_ws(self, module_db, provider="docker", meta=None):
        from app import models
        from app.core.utils import new_id, ts_now

        admin = module_db.query(models.User).filter_by(username=ADMIN).first()
        ws = models.OperatorWorkstation(
            id=new_id("ws"),
            project_id=_s["pid"],
            user_id=admin.id,
            template_id="builtin-kali-minimal",
            name="ws-force-test",
            provider=provider,
            status="ready",
            created_at=ts_now(),
            meta=meta or {},
        )
        module_db.add(ws)
        module_db.commit()
        return ws

    def test_docker_teardown_exception_keeps_record(self, module_client, module_db):
        from unittest.mock import patch

        ws = self._make_ws(module_db, meta={"container_name": "ws-xyz"})
        with patch(
            "asyncio.create_subprocess_exec",
            side_effect=Exception("docker daemon unreachable"),
        ):
            r = module_client.delete(f"/api/workstations/{ws.id}/force")
        assert r.status_code == 500
        assert "docker compose down failed" in r.json()["detail"]
        from app import models

        row = module_db.query(models.OperatorWorkstation).filter_by(id=ws.id).first()
        assert row is not None  # record kept
        assert row.status == "failed"
        assert "docker compose down failed" in (row.meta or {}).get("teardown_error", "")

    def test_compose_down_nonzero_rc_keeps_record(self, module_client, module_db):
        from unittest.mock import AsyncMock, MagicMock, patch

        ws = self._make_ws(module_db, meta={"container_name": "ws-rc"})
        proc = MagicMock()
        proc.returncode = 1
        proc.communicate = AsyncMock(return_value=(b"", b"no such project"))
        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
            r = module_client.delete(f"/api/workstations/{ws.id}/force")
        assert r.status_code == 500
        assert "exited 1" in r.json()["detail"]
        from app import models

        row = module_db.query(models.OperatorWorkstation).filter_by(id=ws.id).first()
        assert row is not None
        assert row.status == "failed"

    def test_cloud_destroy_failure_keeps_record(self, module_client, module_db):
        from unittest.mock import patch

        import app.ee.workstation.cloud_providers as _cc

        ws = self._make_ws(module_db, provider="hetzner")
        with patch(
            "app.ee.workstation.provider.destroy_workstation",
            side_effect=Exception("hetzner api 500"),
        ), patch.object(_cc, "_state_path", side_effect=Exception("no state")):
            r = module_client.delete(f"/api/workstations/{ws.id}/force")
        assert r.status_code == 500
        assert "cloud destroy failed" in r.json()["detail"]
        from app import models

        row = module_db.query(models.OperatorWorkstation).filter_by(id=ws.id).first()
        assert row is not None
        assert row.status == "failed"
        assert "cloud destroy failed" in (row.meta or {}).get("teardown_error", "")

    def test_cloud_state_cleanup_failure_keeps_record(self, module_client, module_db):
        from unittest.mock import AsyncMock, patch

        import app.ee.workstation.cloud_providers as _cc

        ws = self._make_ws(module_db, provider="hetzner")
        with patch(
            "app.ee.workstation.provider.destroy_workstation", new=AsyncMock()
        ), patch.object(_cc, "_state_path", side_effect=Exception("fs error")):
            r = module_client.delete(f"/api/workstations/{ws.id}/force")
        assert r.status_code == 500
        assert "cloud state cleanup failed" in r.json()["detail"]
        from app import models

        row = module_db.query(models.OperatorWorkstation).filter_by(id=ws.id).first()
        assert row is not None
        assert "cloud state cleanup failed" in (row.meta or {}).get("teardown_error", "")

    def test_successful_teardown_removes_record(self, module_client, module_db):
        from unittest.mock import AsyncMock, MagicMock, patch

        ws = self._make_ws(module_db, meta={"container_name": "ws-ok"})
        proc = MagicMock()
        proc.returncode = 0
        proc.communicate = AsyncMock(return_value=(b"", b""))
        with patch("asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
            r = module_client.delete(f"/api/workstations/{ws.id}/force")
        assert r.status_code == 200
        from app import models

        row = module_db.query(models.OperatorWorkstation).filter_by(id=ws.id).first()
        assert row is None


class TestProvisionBackgroundCancelled:
    """2026-09-08 test3 incident: a cancelled provisioning task (server
    restart) must mark the row failed WITH a reason, not die silently and
    not leave it provisioning forever."""

    @pytest.mark.asyncio
    async def test_cancelled_task_marks_failed_with_reason(self, monkeypatch):
        import asyncio

        from app.routers import workstations as ws_router

        raised = {}

        async def fake_provision(ws, db):
            raise asyncio.CancelledError()

        monkeypatch.setattr(
            "app.ee.workstation.provider.provision_workstation", fake_provision
        )

        class _Q:
            def __init__(self, row):
                self._row = row

            def filter(self, *a, **k):
                return self

            def with_for_update(self, *a, **k):
                return self

            def first(self):
                return self._row

        row = type("Row", (), {})()
        row.id = "ws_cancel_test"
        row.status = "provisioning"
        row.meta = {}

        class _DB:
            def query(self, *a, **k):
                return _Q(row)

            def commit(self):
                raised["committed"] = True

            def close(self):
                pass

        monkeypatch.setattr(ws_router, "SessionLocal", lambda: _DB())

        with pytest.raises(asyncio.CancelledError):
            await ws_router._ws_provision_background("ws_cancel_test")

        assert row.status == "failed"
        assert "cancelled" in (row.meta or {}).get("error", "").lower()
        assert raised.get("committed") is True

    @pytest.mark.asyncio
    async def test_exception_logged_and_persisted(self, monkeypatch):
        from app.routers import workstations as ws_router

        async def fake_provision(ws, db):
            raise RuntimeError("boom-k8s")

        monkeypatch.setattr(
            "app.ee.workstation.provider.provision_workstation", fake_provision
        )

        class _Q:
            def __init__(self, row):
                self._row = row

            def filter(self, *a, **k):
                return self

            def with_for_update(self, *a, **k):
                return self

            def first(self):
                return self._row

        row = type("Row", (), {})()
        row.id = "ws_exc_test"
        row.status = "provisioning"
        row.meta = {}

        class _DB:
            def query(self, *a, **k):
                return _Q(row)

            def commit(self):
                pass

            def close(self):
                pass

        monkeypatch.setattr(ws_router, "SessionLocal", lambda: _DB())
        await ws_router._ws_provision_background("ws_exc_test")  # no raise

        assert row.status == "failed"
        assert "boom-k8s" in (row.meta or {}).get("error", "")


class TestDestroyRouting:
    """Template k8s machines (provider=kubernetes) must tear down via
    destroy_kubernetes even though they join the pool (is_pool=True);
    pool k8s machines (provider=k8s) via the pool teardown."""

    @pytest.mark.asyncio
    async def test_template_k8s_routes_to_destroy_kubernetes(self, monkeypatch):
        from unittest.mock import AsyncMock, MagicMock

        from app.ee.workstation import provider as prov_mod

        ws = MagicMock()
        ws.provider = "kubernetes"
        ws.is_pool = True
        ws.meta = {"k8s_name": "x", "k8s_namespace": "default"}
        dk = AsyncMock()
        dp = MagicMock()
        # destroy_workstation imports destroy_kubernetes inside the function
        # body, so the module attribute is what has to be replaced — which is
        # exactly what setattr on this dotted path does. It must go through
        # monkeypatch: a raw `cp.destroy_kubernetes = dk` is never undone and
        # leaked the AsyncMock into every later test in the session (it broke
        # test_ws_unbound_destroy, which calls the real function).
        monkeypatch.setattr("app.ee.workstation.cloud_providers.destroy_kubernetes", dk)
        monkeypatch.setattr(prov_mod, "destroy_via_infra_provider", dp, raising=False)

        await prov_mod.destroy_workstation(ws, MagicMock())
        dk.assert_awaited_once()
        dp.assert_not_called()

    @pytest.mark.asyncio
    async def test_pool_k8s_routes_to_pool_teardown(self, monkeypatch):
        from unittest.mock import AsyncMock, MagicMock

        from app.ee.workstation import pool_provisioning as pool_prov_mod
        from app.ee.workstation import provider as prov_mod

        ws = MagicMock()
        ws.provider = "k8s"
        ws.is_pool = True
        ws.meta = {"k8s_pod": "umbryx-pool-x"}
        dk = AsyncMock()
        teardown = MagicMock()
        # Both must be monkeypatched, not assigned: raw assignment here leaked
        # into the rest of the session.
        monkeypatch.setattr("app.ee.workstation.cloud_providers.destroy_kubernetes", dk)
        monkeypatch.setattr(pool_prov_mod, "destroy_via_infra_provider", teardown, raising=False)

        await prov_mod.destroy_workstation(ws, MagicMock())
        teardown.assert_called_once()
        dk.assert_not_awaited()
