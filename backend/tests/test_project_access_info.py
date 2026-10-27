"""Output → Access: project access-info aggregation (C2 creds, infra creds, machines)."""

from app import models as m
from app.core.utils import new_id, ts_now


def _login(c, username="admin", password="TestPass1234!"):
    c.post("/api/auth/login", json={"username": username, "password": password})


def _mk_project(db, name="access-info-proj"):
    p = m.Project(id=new_id("p"), name=name, status="active", added=ts_now())
    db.add(p)
    db.commit()
    return p


def _mk_member(db, pid, user_id, role="operator"):
    db.add(m.ProjectMember(id=new_id("pm"), project_id=pid, user_id=user_id, role=role, created_at=ts_now()))
    db.commit()


def _mk_integration(db, name, pids, url="https://c2.example:8443", username="op", password="pw123", itype="adaptix"):
    from app.routers.c2._integrations import _load_integrations, _save_integrations

    lst = _load_integrations(db)
    lst.append({
        "id": new_id("c2"), "name": name, "type": itype, "url": url, "token": "",
        "username": username, "password": password, "endpoint": "/endpoint",
        "verify_ssl": False, "project_ids": pids, "enabled": True, "sync_interval_minutes": 0,
        "created_by": "test", "last_sync": None,
    })
    _save_integrations(db, lst)
    return lst[-1]["id"]


def _mk_cred(db, pid, stack, service, label="Admin Access", username="admin", secret="s3cret", roles=None):
    c = m.ServiceCredential(
        id=new_id("icred"), stack_id=stack.id, service_id=service.id if service else None,
        project_id=pid, purpose="admin_access", label=label, username=username,
        secret=secret, url=service.connection_url if service else None,
        visible_to_roles=roles if roles is not None else ["operator", "analyst"], created_at=ts_now(),
    )
    db.add(c)
    db.commit()
    return c


def _mk_stack(db, pid, name="test-stack", svc_url="https://svc.example:9443"):
    stack = m.InfraStack(id=new_id("stk"), project_id=pid, name=name, status="ready", created_at=ts_now())
    db.add(stack)
    db.commit()
    svc = m.StackService(id=new_id("svs"), stack_id=stack.id, name=f"{name}-c2", role="c2",
                         connection_url=svc_url)
    db.add(svc)
    db.commit()
    return stack, svc


class TestProjectAccessInfo:
    def test_aggregates_all_three_sections(self, module_client, module_db):
        _login(module_client)
        p = _mk_project(module_db)
        _mk_integration(module_db, "team-c2", [p.id])
        stack, svc = _mk_stack(module_db, p.id)
        _mk_cred(module_db, p.id, stack, svc)
        ws = m.OperatorWorkstation(id=new_id("ws"), name="m1", provider="manual", status="ready",
                                   access_address="10.0.0.9:2222", created_at=ts_now(), ready_at=ts_now(),
                                   is_pool=True, project_id=p.id, meta={"ssh_user": "root"})
        module_db.add(ws)
        module_db.commit()

        r = module_client.get(f"/api/projects/{p.id}/access-info")
        assert r.status_code == 200, r.text
        d = r.json()
        assert len(d["c2"]) == 1
        assert d["c2"][0]["password"] == "pw123"  # расшифрован
        assert "Browser" in d["c2"][0]["how_to"]
        assert len(d["infra"]) == 1
        assert d["infra"][0]["secret"] == "s3cret"
        assert d["infra"][0]["url"].startswith("https://svc.example")
        assert len(d["machines"]) == 1
        assert d["machines"][0]["ssh_cmd"] == "ssh root@10.0.0.9 -p 2222"
        assert d["machines"][0]["my_access"] is False

        # cleanup
        from app.routers.c2._integrations import _C2_SETTING_KEY
        item = module_db.query(m.GlobalSetting).filter(m.GlobalSetting.key == _C2_SETTING_KEY).first()
        item.value = [i for i in item.value if i.get("name") != "team-c2"]
        module_db.commit()
        module_db.query(m.OperatorWorkstation).filter_by(id=ws.id).delete()
        module_db.query(m.ServiceCredential).filter(m.ServiceCredential.project_id == p.id).delete()
        module_db.query(m.StackService).filter_by(id=svc.id).delete()
        module_db.query(m.InfraStack).filter_by(id=stack.id).delete()
        module_db.query(m.Project).filter_by(id=p.id).delete()
        module_db.commit()

    def test_role_visibility_filter(self, module_client, module_db):
        _login(module_client)
        p = _mk_project(module_db, "role-filter-proj")
        stack, svc = _mk_stack(module_db, p.id, "stack-viz")
        _mk_cred(module_db, p.id, stack, svc, label="operators only", roles=["operator"])

        # admin видит всё
        r = module_client.get(f"/api/projects/{p.id}/access-info")
        assert len(r.json()["infra"]) == 1

        # viewer-роль не видит кред с visible_to_roles=[operator]
        r = module_client.post("/api/admin/users", json={"username": "viz_user_ai", "password": "TestPass1234!", "role": "user"})
        viz_id = r.json()["id"]
        _mk_member(module_db, p.id, viz_id, role="viewer")
        module_client.post("/api/auth/login", json={"username": "viz_user_ai", "password": "TestPass1234!"})
        r = module_client.get(f"/api/projects/{p.id}/access-info")
        assert r.status_code == 200
        assert r.json()["infra"] == []
        module_client.post("/api/auth/login", json={"username": "admin", "password": "TestPass1234!"})

        module_db.query(m.ServiceCredential).filter(m.ServiceCredential.project_id == p.id).delete()
        module_db.query(m.StackService).filter_by(id=svc.id).delete()
        module_db.query(m.InfraStack).filter_by(id=stack.id).delete()
        module_db.query(m.User).filter_by(id=viz_id).delete()
        module_db.query(m.Project).filter_by(id=p.id).delete()
        module_db.commit()

    def test_viewer_gets_no_secret_values(self, module_client, module_db):
        """Security audit 2026-10-07 (finding 5): roles holding only
        credentials.read (viewer) must see the integration/cred list but
        NOT the decrypted password/token/secret values."""
        _login(module_client)
        p = _mk_project(module_db, "secret-gate-proj")
        stack, svc = _mk_stack(module_db, p.id, "stack-sec")
        _mk_cred(module_db, p.id, stack, svc, label="admin access", roles=[])
        _mk_integration(module_db, "integ-sec", [p.id])

        r = module_client.post("/api/admin/users", json={"username": "viz_sec", "password": "TestPass1234!", "role": "user"})
        viz_id = r.json()["id"]
        _mk_member(module_db, p.id, viz_id, role="viewer")
        module_client.post("/api/auth/login", json={"username": "viz_sec", "password": "TestPass1234!"})
        r = module_client.get(f"/api/projects/{p.id}/access-info")
        assert r.status_code == 200
        d = r.json()
        assert d["infra"] and d["infra"][0]["secret"] == ""
        assert d["c2"] and d["c2"][0]["password"] == "" and d["c2"][0]["token"] == ""

        module_client.post("/api/auth/login", json={"username": "admin", "password": "TestPass1234!"})
        r = module_client.get(f"/api/projects/{p.id}/access-info")
        assert r.json()["infra"][0]["secret"] == "s3cret"
        assert r.json()["c2"][0]["password"] == "pw123"

        from app.routers.c2._integrations import _C2_SETTING_KEY
        item = module_db.query(m.GlobalSetting).filter(m.GlobalSetting.key == _C2_SETTING_KEY).first()
        if item:
            item.value = [i for i in item.value if i.get("name") != "integ-sec"]
        module_db.query(m.ServiceCredential).filter(m.ServiceCredential.project_id == p.id).delete()
        module_db.query(m.StackService).filter_by(id=svc.id).delete()
        module_db.query(m.InfraStack).filter_by(id=stack.id).delete()
        module_db.query(m.ProjectMember).filter_by(user_id=viz_id).delete()
        module_db.query(m.User).filter_by(id=viz_id).delete()
        module_db.query(m.Project).filter_by(id=p.id).delete()
        module_db.commit()

    def test_non_member_forbidden(self, module_client, module_db):
        _login(module_client)
        p = _mk_project(module_db, "closed-proj")
        r = module_client.post("/api/admin/users", json={"username": "outsider_ai", "password": "TestPass1234!", "role": "user"})
        uid = r.json()["id"]
        module_client.post("/api/auth/login", json={"username": "outsider_ai", "password": "TestPass1234!"})
        r = module_client.get(f"/api/projects/{p.id}/access-info")
        assert r.status_code in (403, 404)  # 404 = скрытие существования
        module_client.post("/api/auth/login", json={"username": "admin", "password": "TestPass1234!"})
        module_db.query(m.Project).filter_by(id=p.id).delete()
        module_db.query(m.User).filter_by(id=uid).delete()
        module_db.commit()


class TestDroppedPayloadGate:
    """Dropper URLs are unauthenticated payload download links by design —
    they must not reach roles without READ_SECRET (the same treatment C2
    passwords got in audit finding 5), while operator roles keep them."""

    def _mk_dropped(self, db, pid, n=2):
        for i in range(n):
            db.add(m.Loot(
                id=new_id("lt"), pid=pid, loot_type="file", value=f"implant{i}.exe",
                filename=f"implant{i}.exe", sha256=f"aa{i}", artifact_type="file",
                dropper_url=f"https://drop.example/p{i}", ts=ts_now(),
            ))
        db.commit()

    def test_viewer_gets_count_but_no_links(self, module_client, module_db):
        _login(module_client)
        p = _mk_project(module_db, "drop-gate-proj")
        self._mk_dropped(module_db, p.id, 2)
        r = module_client.post("/api/admin/users", json={"username": "viz_drop", "password": "TestPass1234!", "role": "user"})
        viz_id = r.json()["id"]
        _mk_member(module_db, p.id, viz_id, role="viewer")
        module_client.post("/api/auth/login", json={"username": "viz_drop", "password": "TestPass1234!"})
        r = module_client.get(f"/api/projects/{p.id}/access-info")
        assert r.status_code == 200
        d = r.json()
        assert d["dropped"] == []
        assert d["dropped_total"] == 2
        assert d["dropped_restricted"] is True

        # operator keeps full links
        module_client.post("/api/auth/login", json={"username": "admin", "password": "TestPass1234!"})
        d = module_client.get(f"/api/projects/{p.id}/access-info").json()
        assert len(d["dropped"]) == 2
        assert d["dropped"][0]["url"].startswith("https://drop.example/")
        assert d["dropped_restricted"] is False

        module_db.query(m.ProjectMember).filter_by(user_id=viz_id).delete()
        module_db.query(m.User).filter_by(id=viz_id).delete()
        module_db.query(m.Loot).filter(m.Loot.pid == p.id).delete()
        module_db.query(m.Project).filter_by(id=p.id).delete()
        module_db.commit()
