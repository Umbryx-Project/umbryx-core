"""Workstation → SSH-executor bridge (2026-09-22).

Two product flows covered:
  * attach an already-deployed machine as a workstation (register-manual
    with own credentials + connectivity probe),
  * make any workstation the SSH executor machine — it becomes a
    first-class attacker target for scans / attacker-exec / pivots without
    credentials ever being copied into the attacker-target settings store.
"""


import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.crypto import decrypt_str, encrypt_str
from app.plugins import state as plugin_state

from ._license_test_utils import license_ee


def _admin(client: TestClient):
    from tests.test_workstation_pool import _admin as _pool_admin

    return _pool_admin(client)


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient, module_db: Session):
    """A manual PlatformOps provider for pool-create tests (no external
    calls) and the attacker_ssh module switched on for admin CRUD guards."""
    from app import models
    from app.core.utils import new_id, ts_now

    module_db.add(
        models.InfraProvider(
            id=new_id("iprv"), name="exec-lab", type="manual", category="cloud", created_at=ts_now()
        )
    )
    module_db.commit()
    _admin(module_client)
    # Deployment is Enterprise-only (docs/modules/EDITIONS.md): these
    # tests drive it, so the instance has to hold a real license.
    undo = license_ee(module_client, module_db)
    yield
    undo()


class TestRegisterManualWithAuth:
    def test_password_auth_stored_encrypted_and_probe_ok(self, module_client: TestClient, module_db: Session, monkeypatch):
        _admin(module_client)
        from app.core.workstation import pool as pool_mod


        seen = {}

        def fake_run_ssh(config, cmd):
            seen.update(config)
            return "umbryx-probe-ok"

        monkeypatch.setattr(pool_mod, "_run_ssh", fake_run_ssh)
        r = module_client.post(
            "/api/workstations/pool/x/register-manual",
            json={
                "name": "imported-vm",
                "access_address": "10.99.0.99:2222",
                "ssh_user": "ops",
                "auth": {"type": "password", "secret": "S3cretPass"},
            },
        )
        assert r.status_code == 201, r.text
        body = r.json()
        assert body["status"] == "ready"
        assert body["ssh_auth_type"] == "password"
        # probe used the machine's own credentials, not the platform key
        assert seen["host"] == "10.99.0.99"
        assert seen["port"] == 2222
        assert seen["username"] == "ops"
        assert seen["password"] == "S3cretPass"
        assert seen["private_key"] == ""
        # stored encrypted, never plaintext
        from app import models

        ws = module_db.query(models.OperatorWorkstation).filter_by(id=body["id"]).first()
        secret = ws.meta["ssh_auth"]["secret"]
        assert "S3cretPass" not in secret
        assert decrypt_str(secret) == "S3cretPass"

    def test_probe_failure_records_error_status(self, module_client: TestClient, module_db: Session, monkeypatch):
        _admin(module_client)
        from app.core.workstation import pool as pool_mod


        def boom(config, cmd):
            raise RuntimeError("Connection refused")

        monkeypatch.setattr(pool_mod, "_run_ssh", boom)
        r = module_client.post(
            "/api/workstations/pool/x/register-manual",
            json={"name": "dead-vm", "access_address": "10.99.0.98", "auth": {"type": "password", "secret": "x"}},
        )
        assert r.status_code == 201, r.text
        assert r.json()["status"] == "error"
        assert "Connection refused" in r.json()["error"]

    def test_invalid_auth_rejected(self, module_client: TestClient):
        _admin(module_client)
        r = module_client.post(
            "/api/workstations/pool/x/register-manual",
            json={"name": "vm", "access_address": "10.0.0.1", "auth": {"type": "password"}},
        )
        assert r.status_code == 400
        r = module_client.post(
            "/api/workstations/pool/x/register-manual",
            json={"name": "vm", "access_address": "10.0.0.1", "auth": {"type": "kerberos", "secret": "x"}},
        )
        assert r.status_code == 400


@pytest.mark.ee
class TestExecutorBridge:
    def _ready_ws(self, module_db: Session, pid=None, auth=None):
        import uuid

        from app import models

        meta = {"ssh_user": "root", "ssh_port": 22}
        if auth:
            meta["ssh_auth"] = {"type": auth[0], "secret": encrypt_str(auth[1])}
        ws = models.OperatorWorkstation(
            id="wstest" + uuid.uuid4().hex[:8],
            project_id=pid,
            name="exec-box",
            provider="manual",
            status="ready",
            access_address="10.99.7.7",
            created_at="2026-09-22T00:00:00Z",
            ready_at="2026-09-22T00:00:00Z",
            is_pool=True,
            meta=meta,
        )
        module_db.add(ws)
        module_db.commit()
        return ws

    def test_enabled_machine_becomes_attacker_target(self, module_client: TestClient, module_db: Session, monkeypatch):
        _admin(module_client)
        from app.core.workstation import pool as pool_mod


        monkeypatch.setattr(pool_mod, "_run_ssh", lambda c, cmd: "umbryx-probe-ok")
        r = module_client.post(
            "/api/projects", json={"name": "Executor Bridge 1", "added": "2026-09-22T00:00:00Z", "status": "active"}
        )
        assert r.status_code in (200, 201), r.text
        pid = r.json()["id"]

        ws = self._ready_ws(module_db, pid=pid, auth=("password", "box-pass"))
        r = module_client.post(f"/api/workstations/{ws.id}/executor", json={"enabled": True, "scope": "project"})
        assert r.status_code == 200, r.text

        targets = plugin_state.list_attacker_targets(module_db)
        t = next((x for x in targets if x.get("id") == f"ws:{ws.id}"), None)
        assert t is not None
        assert t["source"] == "workstation"
        assert t["is_operator"] is True
        assert t["host"] == "10.99.7.7"
        assert t["password"] == "box-pass"
        assert t["project_ids"] == [pid]

        # scan-style resolution sees it for the project
        from app.core.attacker_transport import list_global_targets_for_project

        names = [x["id"] for x in list_global_targets_for_project(pid)]
        assert f"ws:{ws.id}" in names

    def test_scope_all_and_unbound_project_scope(self, module_client: TestClient, module_db: Session):
        _admin(module_client)
        # scope=project without a bound project → 400
        ws = self._ready_ws(module_db)
        r = module_client.post(f"/api/workstations/{ws.id}/executor", json={"enabled": True, "scope": "project"})
        assert r.status_code == 400
        # scope=all works unbound, visible to every project
        r = module_client.post(f"/api/workstations/{ws.id}/executor", json={"enabled": True, "scope": "all"})
        assert r.status_code == 200, r.text
        t = next(x for x in plugin_state.list_attacker_targets(module_db) if x.get("id") == f"ws:{ws.id}")
        assert t["project_ids"] == []
        # disable → gone
        r = module_client.post(f"/api/workstations/{ws.id}/executor", json={"enabled": False})
        assert r.status_code == 200
        assert not any(
            x.get("id") == f"ws:{ws.id}" for x in plugin_state.list_attacker_targets(module_db)
        )

    def test_save_never_persists_workstation_targets(self, module_client: TestClient, module_db: Session):
        _admin(module_client)
        ws = self._ready_ws(module_db, auth=("password", "p1"))
        ws.meta = {**ws.meta, "executor": {"enabled": True, "scope": "all"}}
        module_db.commit()

        targets = plugin_state.list_attacker_targets(module_db)
        assert any(t.get("id") == f"ws:{ws.id}" for t in targets)
        # a save round-trip (admin CRUD path) must not duplicate it into the store
        plugin_state.save_attacker_targets(targets, module_db)
        raw = plugin_state.load_attacker_ssh_config(module_db).get("targets", [])
        assert not any(t.get("id") == f"ws:{ws.id}" or t.get("source") == "workstation" for t in raw)
        # and the merged view still shows exactly one
        merged = [t for t in plugin_state.list_attacker_targets(module_db) if t.get("id") == f"ws:{ws.id}"]
        assert len(merged) == 1

    def test_admin_crud_rejects_workstation_targets(self, module_client: TestClient, module_db: Session, monkeypatch):
        _admin(module_client)
        # module-enablement isn't under test here — the builtin registry is
        # only populated by the production startup path.
        from app.routers import system_modules as sm

        monkeypatch.setattr(sm, "_require_attacker_module_enabled", lambda: None)
        ws = self._ready_ws(module_db)
        ws.meta = {**ws.meta, "executor": {"enabled": True, "scope": "all"}}
        module_db.commit()
        tid = f"ws:{ws.id}"

        existing = next(t for t in plugin_state.list_attacker_targets(module_db) if t.get("id") == tid)
        base = {
            "name": existing["name"], "host": existing["host"], "port": existing["port"],
            "username": existing["username"], "password": "x", "private_key": "",
            "known_hosts_policy": "accept_new", "proxy_type": "", "proxy_host": "", "proxy_port": 0,
            "proxy_username": "", "proxy_password": "", "proxy_private_key": "",
            "exec_proxy_type": "", "exec_proxy_host": "", "exec_proxy_port": 0, "exec_proxy_username": "",
            "exec_proxy_password": "", "exec_jump_host": "", "exec_jump_port": 0, "exec_jump_username": "",
            "project_ids": [], "enabled": True, "is_operator": True, "runs_pivot": True,
        }
        r = module_client.patch(f"/api/admin/modules/attacker-ssh/targets/{tid}", json=base)
        assert r.status_code == 400
        r = module_client.delete(f"/api/admin/modules/attacker-ssh/targets/{tid}")
        assert r.status_code == 400
        # still there
        assert any(t.get("id") == tid for t in plugin_state.list_attacker_targets(module_db))

    def test_pool_create_make_executor(self, module_client: TestClient, module_db: Session, monkeypatch):
        _admin(module_client)
        from app.ee.workstation import pool_provisioning as pool_prov_mod


        captured = {}

        def fake_provision(ws, db):
            ws.status = "ready"
            ws.ready_at = "2026-09-22T00:00:00Z"
            ws.access_address = "10.99.9.9:22"
            db.commit()
            captured["ws"] = ws

        monkeypatch.setattr(pool_prov_mod, "provision_pool_machine", fake_provision)
        prov = module_client.get("/api/workstations/pool/providers").json()
        docker_prov = next((p for p in prov if p["type"] in ("docker", "manual", "ssh_host")), prov[0])
        r = module_client.post(
            "/api/workstations/pool",
            json={
                "name": "auto-exec-box",
                "infra_provider_id": docker_prov["id"],
                "make_executor": True,
                "executor_scope": "all",
            },
        )
        assert r.status_code == 201, r.text
        assert r.json()["executor"] == {"enabled": True, "scope": "all"}
        assert any(
            t.get("id") == f"ws:{r.json()['id']}" for t in plugin_state.list_attacker_targets(module_db)
        )


class TestProbeOnGrants:
    def test_grant_uses_own_credentials(self, module_client: TestClient, module_db: Session, monkeypatch):
        """authorized_keys edits on an imported machine must authenticate with
        the machine's own stored secret, not the platform key."""
        _admin(module_client)
        from app.core.workstation import pool as pool_mod


        monkeypatch.setattr(
            pool_mod, "_run_ssh", lambda c, cmd: "umbryx-probe-ok" if "probe" in cmd else "0"
        )

        r = module_client.post("/api/admin/users", json={"username": "execu1", "password": "Passw0rd!xyz1", "role": "user"})
        assert r.status_code in (200, 201), r.text
        uid = r.json()["id"]
        from tests.test_workstation_pool import _gen_openssh_key

        # keys are added by the profile owner (no admin-side key creation)
        module_client.post("/api/auth/logout")
        module_client.post("/api/auth/login", json={"username": "execu1", "password": "Passw0rd!xyz1"})
        r = module_client.post(
            "/api/user/ssh-keys",
            json={"name": "k1", "public_key": _gen_openssh_key("exec-test")},
        )
        assert r.status_code in (200, 201), r.text
        _admin(module_client)
        key_id = r.json()["id"]

        r = module_client.post(
            "/api/workstations/pool/x/register-manual",
            json={
                "name": "imported-grant",
                "access_address": "10.99.8.8",
                "auth": {"type": "private_key", "secret": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n"},
            },
        )
        assert r.status_code == 201, r.text
        ws_id = r.json()["id"]

        seen = {}
        monkeypatch.setattr(pool_mod, "_run_ssh", lambda c, cmd: (seen.update(c), "0")[1])
        r = module_client.post(f"/api/workstations/pool/{ws_id}/assign", json={"user_id": uid, "key_id": key_id})
        assert r.status_code == 201, r.text
        assert "abc" in seen.get("private_key", "")
        assert seen.get("password") == ""


class TestInfraAdminVisibility:
    """Org-level infra access: pool / executor / proxies endpoints accept
    org owner/admin/manager/team_lead (ANY org) — not just platform_admin —
    and regular users stay 403. Infra is org infrastructure, not project
    assets, so the selected project's role must not matter."""

    def _mk_org_member(self, module_db: Session, uid: str, org_role: str):
        import uuid

        from app import models
        from app.core.utils import ts_now

        org_id = "org" + uuid.uuid4().hex[:8]
        module_db.add(models.Organization(id=org_id, name="Org " + org_id, slug=org_id, created_at=ts_now()))
        module_db.add(models.OrganizationMember(
            id="om" + uuid.uuid4().hex[:8], org_id=org_id, user_id=uid, role=org_role,
            created_at=ts_now(),
        ))
        module_db.commit()
        return org_id

    def test_org_manager_manages_pool_and_proxies(self, module_client: TestClient, module_db: Session):
        from tests.test_workstation_pool import USER_PASS

        _admin(module_client)
        r = module_client.post("/api/admin/users", json={"username": "orgmgr1", "password": USER_PASS, "role": "user"})
        assert r.status_code in (200, 201), r.text
        mgr_uid = r.json()["id"]
        self._mk_org_member(module_db, mgr_uid, "manager")

        # login as the org manager — no project role anywhere, no platform flag
        module_client.post("/api/auth/logout")
        assert module_client.post("/api/auth/login", json={"username": "orgmgr1", "password": USER_PASS}).status_code == 200

        r = module_client.get("/api/workstations/pool")
        assert r.status_code == 200, r.text
        r = module_client.get("/api/admin/proxies")
        assert r.status_code == 200, r.text
        r = module_client.get("/api/admin/modules/attacker-ssh/config")
        assert r.status_code == 200, r.text

        # executor toggle also infra-admin gated (machine existence aside)
        r = module_client.post("/api/workstations/wsnonexistent/executor", json={"enabled": True, "scope": "all"})
        assert r.status_code == 404, r.text  # not 403 — passed the gate

    def test_plain_user_stays_forbidden(self, module_client: TestClient, module_db: Session):
        from tests.test_workstation_pool import USER_PASS

        _admin(module_client)
        r = module_client.post("/api/admin/users", json={"username": "plainuser1", "password": USER_PASS, "role": "user"})
        assert r.status_code in (200, 201), r.text
        module_client.post("/api/auth/logout")
        assert module_client.post("/api/auth/login", json={"username": "plainuser1", "password": USER_PASS}).status_code == 200

        assert module_client.get("/api/workstations/pool").status_code == 403
        assert module_client.get("/api/admin/proxies").status_code == 403
        assert module_client.get("/api/admin/modules/attacker-ssh/config").status_code == 403
