"""Redeploy must drive the post-deploy integration pipeline result into
the stack status (ARCHITECTURE.md §3 known gap #3).

The pipeline call itself already existed; what was missing is that its
outcome was discarded — a failed integration left the stack "ready" with
no deployment_log event, no degraded status and no websocket refresh.
These tests pin the endpoint's status handling using stubbed engine
methods (a real provision needs SSH/Docker against a provider node).
"""

import pytest

# Enterprise-only: this module imports app.ee at import time, so in a
# Community tree (where the package is removed by scripts/build-ce.sh)
# there is nothing to test rather than something failing. Declared here
# instead of in a list in conftest, so a module that stops depending on
# the Enterprise package can drop the line with it.
pytest.importorskip("app.ee", reason="Enterprise Edition package not in this build")

import pytest
from fastapi.testclient import TestClient

from app.core.utils import new_id, ts_now
from app.ee.infra.engine import ProvisioningEngine
from app.models.infra_v2 import InfraProvider, InfraStack, StackService

from ._license_test_utils import license_ee

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"


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


def _make_stack_with_service(db, name):
    provider = InfraProvider(
        id=new_id("prv"),
        name=f"{name}-provider",
        type="manual",
        category="cloud",
        created_at=ts_now(),
    )
    db.add(provider)
    stack = InfraStack(
        id=new_id("stk"),
        name=name,
        status="ready",
        mode="standalone",
        created_at=ts_now(),
    )
    db.add(stack)
    db.flush()
    svc = StackService(
        id=new_id("svc"),
        stack_id=stack.id,
        provider_id=provider.id,
        role="c2",
        name=f"{name}-svc",
        status="running",
    )
    db.add(svc)
    db.commit()
    return stack, svc


def _redeploy(client, sid, ssid):
    return client.post(f"/api/infra-v2/stacks/{sid}/services/{ssid}/redeploy")


class TestRedeployIntegrationOutcome:
    def test_success_marks_stack_ready_and_logs(self, module_client, module_db, monkeypatch):
        stack, svc = _make_stack_with_service(module_db, "rdy-ok")

        monkeypatch.setattr(
            ProvisioningEngine, "_provision_service", lambda self, stk, s, tr, force=False: None
        )
        monkeypatch.setattr(
            ProvisioningEngine, "_run_post_deploy", lambda self, stk, svcs, ids, tr: True
        )

        r = _redeploy(module_client, stack.id, svc.id)
        assert r.status_code == 200
        assert r.json()["status"] == "ready"

        module_db.expire_all()
        row = module_db.query(InfraStack).get(stack.id)
        assert row.status == "ready"
        assert row.error is None
        events = [e.get("event") for e in (row.deployment_log or [])]
        assert "redeploy_integrated" in events

    def test_integration_failure_degrades_stack(self, module_client, module_db, monkeypatch):
        stack, svc = _make_stack_with_service(module_db, "rdy-fail")

        monkeypatch.setattr(
            ProvisioningEngine, "_provision_service", lambda self, stk, s, tr, force=False: None
        )
        monkeypatch.setattr(
            ProvisioningEngine, "_run_post_deploy", lambda self, stk, svcs, ids, tr: False
        )

        r = _redeploy(module_client, stack.id, svc.id)
        assert r.status_code == 200

        module_db.expire_all()
        row = module_db.query(InfraStack).get(stack.id)
        assert row.status == "degraded"
        assert row.error and "Integration failed" in row.error
        events = [e.get("event") for e in (row.deployment_log or [])]
        assert "redeploy_integration_failed" in events

    def test_pipeline_exception_degrades_stack(self, module_client, module_db, monkeypatch):
        stack, svc = _make_stack_with_service(module_db, "rdy-exc")

        def _boom(self, stk, svcs, ids, tr):
            raise RuntimeError("pipeline exploded")

        monkeypatch.setattr(
            ProvisioningEngine, "_provision_service", lambda self, stk, s, tr, force=False: None
        )
        monkeypatch.setattr(ProvisioningEngine, "_run_post_deploy", _boom)

        r = _redeploy(module_client, stack.id, svc.id)
        assert r.status_code == 200

        module_db.expire_all()
        row = module_db.query(InfraStack).get(stack.id)
        assert row.status == "degraded"

    def test_provision_failure_degrades_stack(self, module_client, module_db, monkeypatch):
        stack, svc = _make_stack_with_service(module_db, "rdy-provfail")

        def _prov_boom(self, stk, s, tr, force=False):
            raise RuntimeError("ssh unreachable")

        monkeypatch.setattr(ProvisioningEngine, "_provision_service", _prov_boom)

        r = _redeploy(module_client, stack.id, svc.id)
        assert r.status_code == 200

        module_db.expire_all()
        row = module_db.query(InfraStack).get(stack.id)
        assert row.status == "degraded"
        svc_row = module_db.query(StackService).get(svc.id)
        assert svc_row.status == "error"
        assert "ssh unreachable" in svc_row.error
