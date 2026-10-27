"""pwndrop dropper integration: facade/auth flow + payload publishing."""

from unittest.mock import MagicMock, patch

import pytest

from app import models as m
from app.core.utils import new_id, ts_now

# Enterprise-only: every test here exercises publishing payloads to a
# stack's pwndrop, which a Community build cannot do. Skipped there
# rather than failed — see conftest.py::pytest_collection_modifyitems.
pytestmark = pytest.mark.ee




class TestPwnDropClient:
    def test_upload_flow(self):
        from app.ee.infra.dropper import PwnDropClient

        client = PwnDropClient("https://drop:443", "admin", "pw", "/sec")
        resp = MagicMock(status_code=200)
        resp.json.return_value = {"data": {"url_path": "/AbCd1234/agent.exe"}}
        with patch.object(client, "_prepare") as prep:
            with patch("app.ee.infra.dropper.httpx.Client") as MC:
                MC.return_value.__enter__.return_value.post.return_value = resp
                url = client.upload("agent.exe", b"MZ...")
        assert url == "/AbCd1234/agent.exe"
        prep.assert_called_once()


def _ensure_project(db, pid="pe827235d"):
    if not db.query(m.Project).filter_by(id=pid).first():
        db.add(m.Project(id=pid, name="dropper-test-proj", status="active", added=ts_now()))
        db.commit()


def _mk_dropper(db, pid, url="https://192.0.2.10:30126", name="PWNDFILE"):
    _ensure_project(db, pid)
    stack = m.InfraStack(id=new_id("stk"), project_id=pid, name="opstack", status="ready", mode="project", created_at=ts_now())
    db.add(stack)
    db.commit()
    svc = m.StackService(id=new_id("svs"), stack_id=stack.id, name=name, role="dropper",
                         connection_url=url, status="running")
    db.add(svc)
    db.commit()
    cred = m.ServiceCredential(id=new_id("icred"), stack_id=stack.id, service_id=svc.id,
                               project_id=pid, purpose="admin_access", label="adm",
                               username="admin", secret="Pw1!", url=url,
                               visible_to_roles=["operator"], created_at=ts_now())
    db.add(cred)
    db.commit()
    return stack, svc, cred


class TestPublishPayload:
    def test_publish_prefers_project_dropper(self, module_db):
        from unittest.mock import patch

        from app.ee.infra.dropper import publish_payload

        stack, svc, cred = _mk_dropper(module_db, "pe827235d")
        with patch("app.ee.infra.dropper.PwnDropClient") as MC:
            MC.return_value.upload.return_value = "/xyz/p.exe"
            res = publish_payload(module_db, "p.exe", b"xx", pid="pe827235d")
        assert res and res["service"] == "PWNDFILE"
        assert res["url"].endswith("/xyz/p.exe")
        MC.return_value.upload.assert_called_once()
        module_db.query(m.ServiceCredential).filter_by(id=cred.id).delete()
        module_db.query(m.StackService).filter_by(id=svc.id).delete()
        module_db.query(m.InfraStack).filter_by(id=stack.id).delete()
        module_db.commit()

    def test_no_dropper_returns_none(self, module_db):
        from app.ee.infra.dropper import publish_payload

        assert publish_payload(module_db, "p.exe", b"xx", pid="p-no-such") is None

    def test_dropped_section_in_access_info(self, module_client, module_db):
        _ensure_project(module_db)
        loot = m.Loot(id=new_id("loot"), pid="pe827235d", loot_type="payload",
                      value="a.exe", filename="a.exe", artifact_type="file",
                      ts=ts_now(), dropper_url="https://d/x/a.exe")
        module_db.add(loot)
        module_db.commit()
        module_client.post("/api/auth/login", json={"username": "admin", "password": "TestPass1234!"})
        r = module_client.get("/api/projects/pe827235d/access-info")
        assert r.status_code == 200
        dropped = r.json().get("dropped", [])
        assert any(d["url"] == "https://d/x/a.exe" for d in dropped)
        module_db.query(m.Loot).filter_by(id=loot.id).delete()
        module_db.commit()
