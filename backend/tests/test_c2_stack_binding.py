"""C2 stacks bind to a project: no shared/unscoped C2 integrations."""

import pytest

from app import models
from app import models as m
from app.core.utils import new_id, ts_now

from ._license_test_utils import license_ee

# Enterprise-only: every test here exercises deploying a stack to check
# C2 binding rules, which a Community build cannot do. Skipped there
# rather than failed — see conftest.py::pytest_collection_modifyitems.
pytestmark = pytest.mark.ee




def _login(c):
    c.post("/api/auth/login", json={"username": "admin", "password": "TestPass1234!"})


@pytest.fixture(scope="module", autouse=True)
def _licensed(module_client, module_db):
    """Deploying a stack is Enterprise-only (docs/modules/EDITIONS.md), and
    every test here deploys one to check the C2 binding rules — so the
    instance holds a real license, the same as a customer running this."""
    module_client.post("/api/auth/setup", json={"username": "admin", "password": "TestPass1234!"})
    _login(module_client)
    undo = license_ee(module_client, module_db)
    yield
    undo()


def _deploy_body(name, with_c2=True, bind=False, pid=None):
    services = [{
        "name": f"{name}-c2", "role": "c2" if with_c2 else "redirector",
        "template_id": None, "deploy_mode": "docker",
        "config": {"image_ref": "adaptix:latest"}, "ports": [],
    }]
    return {
        "name": name, "blueprint_id": None, "services": services,
        "bind_to_project": bind, "project_id": pid, "env_vars": {},
    }


class TestC2StackProjectBinding:
    def test_c2_stack_without_project_rejected(self, module_client, module_db):
        _login(module_client)
        r = module_client.post("/api/infra-v2/stacks/deploy", json=_deploy_body("c2-nopj"))
        assert r.status_code == 400
        assert "bound to a project" in r.json().get("detail") or "bound to a project" in str(r.json().get("message", ""))

    def test_non_c2_stack_standalone_ok(self, module_client, module_db):
        """Standalone allowed for non-C2 roles (validation must not overreach)."""
        import unittest.mock as mock

        _login(module_client)
        with mock.patch("app.ee.routers.infra_v2_api._run_provision_background"):
            r = module_client.post("/api/infra-v2/stacks/deploy", json=_deploy_body("ligolo-nopj", with_c2=False))
        assert r.status_code in (201, 202), r.text
        # cleanup
        sid = r.json().get("id")
        if sid:
            module_db.query(m.StackService).filter_by(stack_id=sid).delete()
            module_db.query(m.InfraStack).filter_by(id=sid).delete()
            module_db.commit()

    def test_register_c2_from_projectless_stack_is_noop(self, module_db):
        from app.ee.routers.infra_v2_api import _register_c2_from_stack

        stack = m.InfraStack(id=new_id("stk"), name="orphan", project_id=None, status="ready", mode="standalone", created_at=ts_now())
        module_db.add(stack)
        module_db.commit()
        svc = m.StackService(id=new_id("svs"), stack_id=stack.id, name="adaptix-x", role="c2",
                             connection_url="https://c2orphan:9443")
        module_db.add(svc)
        module_db.commit()
        assert _register_c2_from_stack(module_db, stack) == 0
        item = module_db.query(m.GlobalSetting).filter_by(key="c2_integrations").first()
        urls = [i.get("url") for i in (item.value if item else []) or []]
        assert "https://c2orphan:9443" not in urls
        module_db.query(m.StackService).filter_by(id=svc.id).delete()
        module_db.query(m.InfraStack).filter_by(id=stack.id).delete()
        module_db.commit()

    def test_register_rescopes_existing_unscoped_integration(self, module_db):
        """Bind flow: an integration registered unscoped earlier gets the
        project appended instead of staying shared."""
        from app.core.crypto import encrypt_str
        from app.ee.routers.infra_v2_api import _register_c2_from_stack

        p = m.Project(id=new_id("p"), name="bind-rescope", status="active", added=ts_now())
        module_db.add(p)
        module_db.commit()
        stack = m.InfraStack(id=new_id("stk"), name="latebind", project_id=p.id, status="ready", mode="project", created_at=ts_now())
        module_db.add(stack)
        module_db.commit()
        svc = m.StackService(id=new_id("svs"), stack_id=stack.id, name="adaptix-y", role="c2",
                             connection_url="https://c2late:9443")
        module_db.add(svc)
        module_db.commit()
        cred = m.ServiceCredential(id=new_id("icred"), stack_id=stack.id, service_id=svc.id,
                                   project_id=p.id, purpose="admin_access", label="adm",
                                   username="admin", secret="pw", url=svc.connection_url,
                                   visible_to_roles=["operator"], created_at=ts_now())
        module_db.add(cred)
        # существующая НЕСКОПИРОВАННАЯ интеграция того же URL (историческая)
        item = module_db.query(m.GlobalSetting).filter_by(key="c2_integrations").first()
        if not item:
            item = m.GlobalSetting(key="c2_integrations", value=[])
            module_db.add(item)
        item.value = list(item.value or []) + [{
            "id": new_id("c2"), "name": "legacy", "type": "adaptix", "url": "https://c2late:9443",
            "token": "", "username": "admin", "password": encrypt_str("old"), "endpoint": "/endpoint",
            "verify_ssl": False, "project_ids": [], "enabled": True, "sync_interval_minutes": 0,
            "created_by": "system", "last_sync": None,
        }]
        module_db.commit()

        _register_c2_from_stack(module_db, stack)
        module_db.refresh(item)
        match = [i for i in item.value if i.get("url") == "https://c2late:9443"]
        assert len(match) == 1
        assert p.id in match[0]["project_ids"]
        assert match[0]["password"] != ""  # сохранена

        # cleanup
        item.value = [i for i in item.value if i.get("url") != "https://c2late:9443"]
        module_db.query(m.ServiceCredential).filter_by(id=cred.id).delete()
        module_db.query(m.StackService).filter_by(id=svc.id).delete()
        module_db.query(m.InfraStack).filter_by(id=stack.id).delete()
        module_db.query(m.Project).filter_by(id=p.id).delete()
        module_db.commit()


class TestPerServiceProjects:
    """Кластер 7×C2: каждый сервис — свой проект, shared edge — стек."""

    def test_deploy_accepts_per_service_projects(self, module_client, module_db):
        _login(module_client)
        p1 = m.Project(id=new_id("p"), name="infra-seg-1", status="active", added=ts_now())
        p2 = m.Project(id=new_id("p"), name="infra-seg-2", status="active", added=ts_now())
        module_db.add_all([p1, p2])
        module_db.commit()

        import unittest.mock as mock

        with mock.patch("app.ee.routers.infra_v2_api._run_provision_background"):
            r = module_client.post(
                "/api/infra-v2/stacks/deploy",
                json={
                    "name": "cluster-7",
                    "services": [
                        {"name": "C2 #1", "role": "c2", "deploy_mode": "docker",
                         "config": {"image_ref": "adaptix:latest"}, "project_id": p1.id},
                        {"name": "C2 #2", "role": "c2", "deploy_mode": "docker",
                         "config": {"image_ref": "adaptix:latest"}, "project_id": p2.id},
                        {"name": "HTTP Redirector", "role": "redirector", "deploy_mode": "docker",
                         "config": {"image_ref": "nginx:latest"}},
                    ],
                    "bind_to_project": False,
                },
            )
        assert r.status_code in (201, 202), r.text
        # C2-сервисы без бинда стека: валидация кластера должна требовать проект?
        # По ТЗ кейса: shared edge может жить без проекта, C2 — обязаны иметь свой
        d = r.json()
        svcs = {s["name"]: s for s in _stack_services(module_db, d["id"])}
        assert svcs["C2 #1"]["project_id"] == p1.id
        assert svcs["C2 #2"]["project_id"] == p2.id
        assert svcs["HTTP Redirector"]["project_id"] is None

        for sid_svc in svcs.values():
            module_db.query(models.StackService).filter_by(id=sid_svc["id"]).delete()
        module_db.query(models.ServiceLink).filter_by(stack_id=d["id"]).delete()
        module_db.query(models.InfraStack).filter_by(id=d["id"]).delete()
        module_db.query(models.Project).filter(models.Project.id.in_([p1.id, p2.id])).delete(synchronize_session=False)
        module_db.commit()

    def test_unknown_project_rejected(self, module_client, module_db):
        _login(module_client)
        r = module_client.post(
            "/api/infra-v2/stacks/deploy",
            json={
                "name": "cluster-bad",
                "services": [
                    {"name": "C2 #1", "role": "c2", "deploy_mode": "docker",
                     "config": {"image_ref": "adaptix:latest"}, "project_id": "pNOPE"},
                ],
                "bind_to_project": False,
            },
        )
        assert r.status_code == 404

    def test_c2_without_any_project_rejected(self, module_client, module_db):
        _login(module_client)
        r = module_client.post(
            "/api/infra-v2/stacks/deploy",
            json={
                "name": "cluster-noscope",
                "services": [
                    {"name": "C2 #X", "role": "c2", "deploy_mode": "docker",
                     "config": {"image_ref": "adaptix:latest"}},
                ],
                "bind_to_project": False,
            },
        )
        assert r.status_code == 400
        assert "must be bound to a project" in r.json()["detail"]


def _stack_services(db, stack_id):
    models = m
    rows = db.query(models.StackService).filter_by(stack_id=stack_id).all()
    return [
        {"id": r.id, "name": r.name, "role": r.role, "project_id": r.project_id}
        for r in rows
    ]
