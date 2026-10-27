"""Unbound (projectless) workstations destroy cleanly — infra_events.pid
is NOT NULL and used to kill every destroy step (2026-10-02)."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

# Enterprise-only: every test here exercises tearing down a provisioned
# machine, which a Community build cannot do. Skipped there rather than
# failed — see conftest.py::pytest_collection_modifyitems.
pytestmark = pytest.mark.ee




def _admin(client: TestClient):
    from tests.test_workstation_pool import _admin as _pool_admin

    return _pool_admin(client)


class TestUnboundDestroy:
    def test_destroy_projectless_machine_completes(self, module_client: TestClient, module_db: Session):
        from app import models
        from app.core.utils import new_id, ts_now

        _admin(module_client)
        ws = models.OperatorWorkstation(
            id=new_id("ws"), name="unbound-destroy", provider="kubernetes",
            status="ready", access_address="10.1.2.3:30123", created_at=ts_now(),
            is_pool=True, project_id=None,
            meta={"ssh_user": "root", "k8s_name": "unbound-destroy", "k8s_namespace": "default"},
        )
        module_db.add(ws)
        module_db.commit()

        import asyncio

        async def fake_run(argv, **kw):
            return {"ok": True, "stdout": "deleted", "stderr": "", "returncode": 0}

        # the guard fix: _log_step must not crash on project_id=None
        from app.ee.workstation.cloud_providers import _log_step, destroy_kubernetes

        _log_step(ws, module_db, "k8s_delete", "deleting…")  # used to raise
        asyncio.run(destroy_kubernetes(ws, module_db))

        import time

        for _ in range(20):
            module_db.expire_all()
            row = module_db.query(models.OperatorWorkstation).filter_by(id=ws.id).first()
            if row is None or row.status not in ("destroying",):
                break
            time.sleep(0.5)
        row = module_db.query(models.OperatorWorkstation).filter_by(id=ws.id).first()
        assert row is not None and row.status == "destroyed", row.status if row else "gone"
