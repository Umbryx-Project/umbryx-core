"""Stack orphan tracking — project deletion must not silently detach stacks.

Covers the known gap from ARCHITECTURE.md §2: DELETE /api/projects/{pid}
relied on the DB-level ondelete="SET NULL" of infra_stacks.project_id, so
bound stacks flipped to standalone with cloud resources still running and
nothing recording why. Now deletion stamps stacks as orphaned
(detached_at / detached_from_project), the stacks API exposes
?orphaned=true, re-binding clears the stamps, and a startup sweep repairs
stacks detached by DB-level cascades.
"""

import pytest
from fastapi.testclient import TestClient

from app.core.devops_log import log_event  # noqa: F401 — import check
from app.core.infra_orphans import stamp_orphaned_stacks
from app.core.utils import new_id, ts_now
from app.models.infra_v2 import InfraStack

from ._license_test_utils import license_ee

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient, module_db):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    # Deployment is Enterprise-only (docs/modules/EDITIONS.md): these
    # tests drive it, so the instance has to hold a real license.
    undo = license_ee(module_client, module_db)
    yield
    undo()


def _make_bound_stack(db, pid, name):
    stack = InfraStack(
        id=new_id("stk"),
        project_id=pid,
        name=name,
        status="ready",
        mode="project",
        bound_at=ts_now(),
        bound_by="u_test",
        created_at=ts_now(),
        created_by="u_test",
    )
    db.add(stack)
    db.commit()
    return stack


@pytest.mark.ee
class TestProjectDeleteOrphans:
    def test_delete_project_stamps_stack(self, module_client, module_db):
        r = module_client.post(
            "/api/projects",
            json={"name": "OrphanProj", "added": "2025-01-01T00:00:00Z", "status": "active"},
        )
        assert r.status_code == 201
        pid = r.json()["id"]
        stack = _make_bound_stack(module_db, pid, "orphan-c2")
        _state["stack_id"] = stack.id
        _state["pid"] = pid

        r = module_client.delete(f"/api/projects/{pid}")
        assert r.status_code == 204

        module_db.expire_all()
        row = module_db.query(InfraStack).get(stack.id)
        assert row is not None, "stack row must survive project deletion"
        assert row.project_id is None
        assert row.mode == "standalone"
        assert row.bound_at is None and row.bound_by is None
        assert row.detached_at, "deletion must stamp detached_at"
        assert row.detached_from_project == pid
        events = [e.get("event") for e in (row.deployment_log or [])]
        assert "orphaned_by_project_delete" in events

    def test_orphaned_filter_lists_stamped_stack(self, module_client):
        r = module_client.get("/api/infra-v2/stacks?orphaned=true")
        assert r.status_code == 200
        ids = [s["id"] for s in r.json()]
        assert _state["stack_id"] in ids
        entry = next(s for s in r.json() if s["id"] == _state["stack_id"])
        assert entry["detached_at"]
        assert entry["detached_from_project"] == _state["pid"]

        r = module_client.get("/api/infra-v2/stacks")
        assert r.status_code == 200
        plain = next(s for s in r.json() if s["id"] == _state["stack_id"])
        assert plain["detached_at"]  # field present on unfiltered list too

    def test_bind_clears_orphan_stamps(self, module_client):
        r = module_client.post(
            "/api/projects",
            json={"name": "OrphanRebind", "added": "2025-01-01T00:00:00Z", "status": "active"},
        )
        assert r.status_code == 201
        new_pid = r.json()["id"]

        r = module_client.post(
            f"/api/infra-v2/stacks/{_state['stack_id']}/bind",
            json={"project_id": new_pid},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["project_id"] == new_pid
        assert body["mode"] == "project"
        assert body["detached_at"] is None
        assert body["detached_from_project"] is None

        r = module_client.get("/api/infra-v2/stacks?orphaned=true")
        assert _state["stack_id"] not in [s["id"] for s in r.json()]

        module_client.delete(f"/api/projects/{new_pid}")  # cleanup, re-orphan

    def test_devops_log_records_orphaning(self, module_client, module_db):
        from app.models.infra_v2 import DevOpsLogEntry

        rows = (
            module_db.query(DevOpsLogEntry)
            .filter(DevOpsLogEntry.stack_id == _state["stack_id"])
            .all()
        )
        assert any("orphaned" in (e.message or "").lower() for e in rows)


class TestStartupSweep:
    def test_sweep_stamps_cascade_detached_stack(self, module_db):
        # Simulate the silent path: a DB-level cascade nulled project_id
        # without anyone stamping the stack (mode stayed "project").
        stack = InfraStack(
            id=new_id("stk"),
            project_id=None,
            name="cascade-orphan",
            status="ready",
            mode="project",
            bound_at=ts_now(),
            created_at=ts_now(),
        )
        module_db.add(stack)
        module_db.commit()

        stamped = stamp_orphaned_stacks(module_db)
        assert stamped >= 1

        module_db.expire_all()
        row = module_db.query(InfraStack).get(stack.id)
        assert row.mode == "standalone"
        assert row.detached_at
        assert row.bound_at is None
        # idempotent: second run finds nothing new
        assert stamp_orphaned_stacks(module_db) == 0
        module_db.delete(row)
        module_db.commit()


class TestOrphanNotifications:
    def test_delete_project_notifies_admins(self, module_client, module_db):
        from app.core.enums import UserRole
        from app.models import User
        from app.models.notification import Notification

        r = module_client.post(
            "/api/projects",
            json={"name": "OrphanNotifyProj", "added": "2025-01-01T00:00:00Z"},
        )
        assert r.status_code == 201
        pid = r.json()["id"]
        _make_bound_stack(module_db, pid, "notify-c2")

        before = (
            module_db.query(Notification)
            .filter(Notification.title.ilike("%notify-c2%"))
            .count()
        )
        assert before == 0

        r = module_client.delete(f"/api/projects/{pid}")
        assert r.status_code == 204

        notes = (
            module_db.query(Notification)
            .filter(Notification.title.ilike("%notify-c2%"))
            .all()
        )
        assert notes, "platform admins must be notified about the orphaned stack"
        admin_ids = {
            u.id
            for u in module_db.query(User).filter(User.role == UserRole.PLATFORM_ADMIN).all()
        }
        assert {n.user_id for n in notes} == admin_ids
        assert all(n.type == "warning" for n in notes)
        assert all("NOT destroyed" in (n.body or "") for n in notes)

    def test_sweep_notifies_admins(self, module_db):
        from app.models.notification import Notification

        stack = InfraStack(
            id=new_id("stk"),
            project_id=None,
            name="sweep-notify",
            status="ready",
            mode="project",
            bound_at=ts_now(),
            created_at=ts_now(),
        )
        module_db.add(stack)
        module_db.commit()

        stamped = stamp_orphaned_stacks(module_db)
        assert stamped >= 1

        notes = (
            module_db.query(Notification)
            .filter(Notification.title.ilike("%sweep-notify%"))
            .all()
        )
        assert notes, "sweep-detached orphans must notify admins too"
        assert all(n.type == "warning" for n in notes)
        module_db.query(InfraStack).filter(InfraStack.id == stack.id).delete()
        module_db.commit()
