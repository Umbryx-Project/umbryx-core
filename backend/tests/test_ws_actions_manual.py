"""Workstation action logging on imported (manual) machines + platform-action mirror."""

from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session


def _admin(client: TestClient):
    from tests.test_workstation_pool import _admin as _pool_admin

    return _pool_admin(client)


_created: list[str] = []


def _manual_ws(module_db: Session) -> str:
    from app import models
    from app.core.utils import new_id, ts_now

    ws = models.OperatorWorkstation(
        id=new_id("ws"),
        name="manual-logger",
        provider="manual",
        status="ready",
        access_address="10.99.0.10",
        created_at=ts_now(),
        is_pool=True,
        meta={"ssh_user": "root", "ssh_port": 22},
    )
    module_db.add(ws)
    module_db.commit()
    _created.append(ws.id)
    return ws.id


import pytest  # noqa: E402


@pytest.fixture(scope="module", autouse=True)
def _cleanup(module_db: Session):
    yield
    from app import models

    for ws_id in _created:
        module_db.query(models.OperatorWorkstation).filter(
            models.OperatorWorkstation.id == ws_id
        ).delete()
    module_db.commit()


class TestHookInstallOverSsh:
    def test_manual_machine_uses_ssh_channel(self, module_client: TestClient, module_db: Session):
        from app import models
        from app.core.workstation import actions as act

        _admin(module_client)
        ws_id = _manual_ws(module_db)
        ws = module_db.query(models.OperatorWorkstation).get(ws_id)

        argv, reason = act._exec_channel(module_db, ws)
        assert argv == ["__ssh__"] and reason is None

    def test_install_hook_runs_over_ssh_not_docker(self, module_client, module_db):
        from app import models
        from app.core.workstation import actions as act

        _admin(module_client)
        ws_id = _manual_ws(module_db)
        ws = module_db.query(models.OperatorWorkstation).get(ws_id)

        with patch("app.core.ssh_exec.run_ssh_command") as ssh, patch(
            "app.core.workstation.actions.subprocess.run"
        ) as sub:
            ssh.return_value = {"ok": True, "stdout": "", "stderr": ""}
            ok, msg = act.install_hook(module_db, ws, "http://x/api", "tok")
        assert ok, msg
        ssh.assert_called_once()
        sub.assert_not_called()  # no docker exec on the backend host
        ws = module_db.query(models.OperatorWorkstation).get(ws_id)
        assert ws.meta["action_log_enabled"] is True

    def test_kubernetes_branch_untouched(self, module_client, module_db):
        from app import models
        from app.core.utils import new_id, ts_now
        from app.core.workstation import actions as act

        _admin(module_client)
        ws = models.OperatorWorkstation(
            id=new_id("ws"), name="k8s-ws", provider="kubernetes", status="ready",
            access_address="10.0.0.1", created_at=ts_now(), is_pool=True,
            meta={"k8s_name": "x", "k8s_namespace": "default"},
        )
        module_db.add(ws)
        module_db.commit()
        argv, reason = act._exec_channel(module_db, ws)
        assert argv and argv[0] == "kubectl" or reason  # kubectl path or its explicit reason


class TestPlatformActionMirror:
    def test_run_command_logs_to_machine_feed(self, module_client: TestClient, module_db: Session):
        """Executing through a ws:<id> executor target mirrors into the
        machine's action log (source platform:attacker-exec)."""
        import asyncio

        from app import models
        from app.core.ai_tools import tool_run_command

        _admin(module_client)
        r = module_client.post(
            "/api/projects",
            json={"name": "Mirror test", "added": "2026-09-26T00:00:00Z", "status": "active"},
        )
        pid = r.json()["id"]
        ws_id = _manual_ws(module_db)

        fake_core_resp = {
            "ok": True, "exit_code": 0, "stdout": "ok", "stderr": "",
            "job_id": "jm1", "activity": {},
            "global_target": {"id": f"ws:{ws_id}"},
        }

        class _FakeCore:
            async def __call__(self, db, pid_, body, username):
                # emulate the mirror inside the real core
                from app.core.workstation.actions import log_platform_action

                log_platform_action(
                    db, ws_id=ws_id, pid=pid_, command=body.command,
                    actor=username or "platform", exit_code=0,
                    origin="attacker-exec",
                )
                return fake_core_resp

        with patch("app.routers.attacker_exec.run_attacker_exec_core", _FakeCore()):
            res = asyncio.run(tool_run_command(module_db, pid, command="whoami", actor_label="ai:admin"))
        assert res["ok"] is True

        rows = (
            module_db.query(models.WorkstationAction)
            .filter(models.WorkstationAction.workstation_id == ws_id)
            .all()
        )
        assert rows, "action not mirrored to the machine feed"
        assert rows[0].source == "platform:attacker-exec"
        assert rows[0].username == "ai:admin"
        assert rows[0].exit_code == 0

    def test_log_platform_action_direct(self, module_client: TestClient, module_db: Session):
        from app.core.workstation.actions import log_platform_action

        _admin(module_client)
        ws_id = _manual_ws(module_db)
        a = log_platform_action(
            module_db, ws_id=ws_id, pid="p1", command="nmap -sV 10.0.0.1",
            actor="admin", exit_code=0, origin="attacker-exec",
        )
        assert a is not None and a.exit_code == 0
        assert a.source == "platform:attacker-exec"


class TestCallbackUrlProbe:
    def test_picks_reachable_candidate(self, module_client, module_db):
        from app import models
        from app.core.workstation import actions as act

        _admin(module_client)
        ws_id = _manual_ws(module_db)
        ws = module_db.query(models.OperatorWorkstation).get(ws_id)

        with patch("app.core.ssh_exec.run_ssh_command") as ssh:
            cands = act._callback_url_candidates(module_db)
            good = cands[0]
            ssh.return_value = {"ok": True, "stdout": f"000 {cands[-1]}\n200 {good}\n", "stderr": ""}
            url, reason = act.pick_callback_url(module_db, ws)
        assert url == good and reason is None

    def test_unreachable_reports_clear_reason(self, module_client, module_db):
        from app import models
        from app.core.workstation import actions as act

        _admin(module_client)
        ws_id = _manual_ws(module_db)
        ws = module_db.query(models.OperatorWorkstation).get(ws_id)

        with patch("app.core.ssh_exec.run_ssh_command") as ssh:
            ssh.return_value = {"ok": True, "stdout": "000 http://x\n", "stderr": ""}
            url, reason = act.pick_callback_url(module_db, ws)
        assert reason and "PUBLIC_BASE_URL" in reason

    def test_candidates_dedupe_and_order(self, module_client, module_db):
        from app.core.workstation import actions as act

        _admin(module_client)
        cands = act._callback_url_candidates(module_db)
        assert len(cands) == len(set(cands))
        assert all(c.startswith("http") for c in cands)


class TestHookBase64Transport:
    def test_install_script_carries_hook_verbatim(self, module_client, module_db):
        """The hook must reach the rc byte-for-byte: no install-time $VAR
        expansion, real newlines, quotes intact (the .zshrc:259 bug)."""
        import base64

        from app import models
        from app.core.workstation import actions as act

        _admin(module_client)
        ws_id = _manual_ws(module_db)
        ws = module_db.query(models.OperatorWorkstation).get(ws_id)

        captured = {}

        def fake_run(cfg, script, timeout):
            captured["script"] = script
            return {"ok": True, "stdout": "installed:/root/.zshrc", "stderr": ""}

        import app.core.ssh_exec as se

        with patch.object(se, "run_ssh_command", fake_run):
            ok, msg = act.install_hook(module_db, ws, "http://p/api", "tok")
        assert ok, msg
        script = captured["script"]
        assert "base64 -d" in script
        # no raw hook fragments in the script itself (everything is b64)
        assert "UMBRYX_LOG_URL=" not in script
        # decode the payload and verify the template survived verbatim
        b64 = script.split("printf '%s' ", 1)[1].split(" | base64", 1)[0]
        hook = base64.b64decode(b64).decode()
        assert hook.count("\n") > 8                      # real newlines
        assert '$UMBRYX_LOG_URL' in hook                  # $ NOT expanded
        assert '${USER:-$(id -un)}' in hook               # intact
        assert "preexec() { __umbryx_log; }" in hook


class TestPullMode:
    def _pull_ws(self, module_db):
        from app import models
        from app.core.utils import new_id, ts_now

        ws = models.OperatorWorkstation(
            id=new_id("ws"), name="pull-ws", provider="manual", status="ready",
            access_address="10.99.0.11", created_at=ts_now(), is_pool=True,
            meta={"ssh_user": "root", "ssh_port": 22, "action_log_enabled": True,
                  "action_log_mode": "pull", "action_log_offset": 0},
        )
        module_db.add(ws)
        module_db.commit()
        _created.append(ws.id)
        return ws

    def test_pull_ingests_lines_and_advances_offset(self, module_client, module_db):
        import json as _json

        from app import models
        from app.core.workstation import actions as act

        _admin(module_client)
        ws = self._pull_ws(module_db)
        lines = "\n".join(
            _json.dumps({
                "ts": f"2026-10-02T17:00:0{i}Z",
                "command": f"nmap -sV 10.0.0.{i}",
                "user": "administrator", "cwd": "/root",
                "ssh_client": f"172.16.90.1 111{i} 22", "tty": "",
            })
            for i in (1, 2)
        )
        with patch("app.core.ssh_exec.run_ssh_command") as ssh:
            ssh.return_value = {"ok": True, "stdout": lines + "\n__SIZE__{}".format(len(lines + "\n")), "stderr": ""}
            n = act.pull_actions(module_db, ws)
        assert n == 2
        rows = module_db.query(models.WorkstationAction).filter(
            models.WorkstationAction.workstation_id == ws.id).all()
        assert len(rows) == 2
        assert rows[0].source == "shell-hook"
        assert rows[0].ssh_client.startswith("172.16.90.1")
        assert ws.meta["action_log_offset"] == len(lines + "\n")

        # second pull with same file → nothing new
        with patch("app.core.ssh_exec.run_ssh_command") as ssh:
            ssh.return_value = {"ok": True, "stdout": "__SIZE__{}".format(len(lines + "\n")), "stderr": ""}
            assert act.pull_actions(module_db, ws) == 0

    def test_truncated_file_resets_offset(self, module_client, module_db):
        import json as _json

        from app.core.workstation import actions as act

        _admin(module_client)
        ws = self._pull_ws(module_db)
        ws.meta["action_log_offset"] = 9999
        module_db.commit()
        line = _json.dumps({"ts": "2026-10-02T17:01:00Z", "command": "whoami",
                            "user": "root", "cwd": "/root", "ssh_client": "", "tty": ""})
        with patch("app.core.ssh_exec.run_ssh_command") as ssh:
            ssh.return_value = {"ok": True, "stdout": line + "\n__SIZE__{}".format(len(line + "\n")), "stderr": ""}
            n = act.pull_actions(module_db, ws)
        assert n == 1
        assert ws.meta["action_log_offset"] == len(line + "\n")

    def test_install_pull_hook_no_network(self, module_client, module_db):
        from app.core.workstation import actions as act

        _admin(module_client)
        ws = self._pull_ws(module_db)
        with patch("app.core.ssh_exec.run_ssh_command") as ssh:
            ssh.return_value = {"ok": True, "stdout": "installed:/root/.zshrc", "stderr": ""}
            ok, msg = act.install_hook(module_db, ws, mode="pull")
        assert ok, msg
        script = ssh.call_args[0][1]
        assert "curl" not in script  # pull hook needs no network at all
        assert "audit.log" in script or "base64 -d" in script


class TestPullScheduler:
    def test_harvest_pulls_every_enabled_machine(self, module_client, module_db):
        """The periodic harvester pulls all enabled pull-mode machines and
        skips disabled/push ones."""
        import json as _json

        from app import models
        from app.core.workstation import actions as act

        _admin(module_client)
        pull_ws = TestPullMode()._pull_ws(module_db)  # enabled pull machine
        # disabled machine — must be skipped
        from app.core.utils import new_id as _nid
        from app.core.utils import ts_now as _ts

        off = models.OperatorWorkstation(
            id=_nid("ws"), name="pull-off", provider="manual", status="ready",
            access_address="10.99.0.12", created_at=_ts(), is_pool=True,
            meta={"ssh_user": "root", "ssh_port": 22, "action_log_enabled": False,
                  "action_log_mode": "pull"},
        )
        module_db.add(off)
        module_db.commit()
        _created.append(off.id)

        line = _json.dumps({"ts": "2026-10-02T18:00:00Z", "command": "curl http://x",
                            "user": "root", "cwd": "/root", "ssh_client": "", "tty": ""})

        calls = []


        import app.core.ssh_exec as se

        def fake_run(cfg, script, timeout):
            calls.append(cfg.get("host"))
            return {"ok": True, "stdout": line + "\n__SIZE__{}".format(len(line + "\n")), "stderr": ""}

        with patch.object(se, "run_ssh_command", fake_run):
            total = act.harvest_pull_machines(module_db)

        assert total >= 1
        assert "10.99.0.12" not in calls  # disabled machine never contacted
        rows = module_db.query(models.WorkstationAction).filter(
            models.WorkstationAction.workstation_id == pull_ws.id
        ).count()
        assert rows == 1


class TestTimelineMirroring:
    def _bound_pull_ws(self, module_db):
        from app import models
        from app.core.utils import new_id, ts_now

        ws = models.OperatorWorkstation(
            id=new_id("ws"), name="tl-ws", provider="manual", status="ready",
            access_address="10.99.0.20", created_at=ts_now(), is_pool=True,
            project_id=_TIDATA["pid"],
            meta={"ssh_user": "root", "ssh_port": 22, "action_log_enabled": True,
                  "action_log_mode": "pull", "action_log_offset": 0},
        )
        module_db.add(ws)
        module_db.commit()
        _created.append(ws.id)
        return ws

    def test_pulled_action_lands_in_timeline(self, module_client, module_db):
        import json as _json

        from app import models
        from app.core.workstation import actions as act

        _admin(module_client)
        r = module_client.post(
            "/api/projects",
            json={"name": "WS timeline", "added": "2026-10-02T00:00:00Z", "status": "active"},
        )
        _TIDATA["pid"] = r.json()["id"]
        ws = self._bound_pull_ws(module_db)
        line = _json.dumps({"ts": "2026-10-02T19:00:00Z", "command": "whoami",
                            "user": "operator1", "cwd": "/root", "ssh_client": "1.2.3.4 5 22", "tty": ""})
        with patch("app.core.ssh_exec.run_ssh_command") as ssh:
            ssh.return_value = {"ok": True, "stdout": line + "\n__SIZE__{}".format(len(line + "\n")), "stderr": ""}
            act.pull_actions(module_db, ws)
        ev = (
            module_db.query(models.TimelineEvent)
            .filter(models.TimelineEvent.pid == _TIDATA["pid"], models.TimelineEvent.entity == "workstation")
            .first()
        )
        assert ev is not None, "no timeline event for pulled action"
        assert "tl-ws" in ev.label and "whoami" in ev.label
        assert ev.username == "operator1"
        assert ev.meta.get("source") == "shell-hook"

    def test_platform_action_lands_in_timeline(self, module_client, module_db):
        from app import models
        from app.core.workstation.actions import log_platform_action

        _admin(module_client)
        ws = self._bound_pull_ws(module_db)
        log_platform_action(
            module_db, ws_id=ws.id, pid=_TIDATA["pid"],
            command="nmap -sV 10.0.0.9", actor="ai:admin", exit_code=0,
            origin="attacker-exec",
        )
        ev = (
            module_db.query(models.TimelineEvent)
            .filter(models.TimelineEvent.pid == _TIDATA["pid"], models.TimelineEvent.entity == "workstation",
                    models.TimelineEvent.label.like("%nmap%"))
            .first()
        )
        assert ev is not None
        assert ev.username == "ai:admin"
        assert ev.meta.get("source") == "platform:attacker-exec"


_TIDATA = {"pid": None}


class TestSessionAttribution:
    def test_fingerprint_names_the_operator(self, module_client, module_db):
        """Local 'root' + ssh_client port → sshd 'Accepted publickey …
        SHA256:<fp>' → the platform user owning that profile key."""
        import json as _json

        from app import models
        from app.core.workstation import actions as act
        from tests.test_workstation_pool import _gen_openssh_key

        _admin(module_client)
        # operator with a profile key (added by the profile owner — the
        # admin endpoint is read-only)
        r = module_client.post("/api/admin/users", json={"username": "opattrib", "password": "Passw0rd!xyz1", "role": "user"})
        uid = r.json()["id"]
        module_client.post("/api/auth/logout")
        assert module_client.post("/api/auth/login", json={"username": "opattrib", "password": "Passw0rd!xyz1"}).status_code == 200
        pub = _gen_openssh_key("attrib-test")
        r = module_client.post("/api/user/ssh-keys", json={"name": "k", "public_key": pub})
        assert r.status_code in (200, 201), r.text
        _admin(module_client)

        from app.core.workstation.pool import fingerprint_of

        fp = fingerprint_of(pub)
        assert fp.startswith("SHA256:")

        ws = TestPullMode()._pull_ws(module_db)
        r = module_client.post("/api/projects", json={"name": "Attrib proj", "added": "2026-10-02T00:00:00Z", "status": "active"})
        ws.project_id = r.json()["id"]
        module_db.commit()
        line = _json.dumps({"ts": "2026-10-02T20:00:00Z", "command": "id",
                            "user": "root", "cwd": "/root",
                            "ssh_client": "172.16.90.1 27982 22", "tty": "/dev/pts/2"})
        sshd_line = (
            f"Oct 02 20:00:01 kali sshd[123]: Accepted publickey for root "
            f"from 172.16.90.1 port 27982 ssh2: ED25519 {fp}"
        )
        with patch("app.core.ssh_exec.run_ssh_command") as ssh:
            def fake(cfg, script, timeout):
                if "journalctl" in script:
                    return {"ok": True, "stdout": sshd_line + "\n", "stderr": ""}
                return {"ok": True, "stdout": line + "\n__SIZE__{}".format(len(line + "\n")), "stderr": ""}
            ssh.side_effect = fake
            act.pull_actions(module_db, ws)

        row = module_db.query(models.WorkstationAction).filter(
            models.WorkstationAction.workstation_id == ws.id
        ).first()
        assert row.username == "opattrib", row.username  # not "root"
        ev = module_db.query(models.TimelineEvent).filter(
            models.TimelineEvent.pid == ws.project_id,
            models.TimelineEvent.entity == "workstation",
        ).first()
        assert ev.username == "opattrib"  # timeline carries the operator too

    def test_no_match_keeps_local_user(self, module_client, module_db):
        import json as _json

        from app import models
        from app.core.workstation import actions as act

        _admin(module_client)
        ws = TestPullMode()._pull_ws(module_db)
        line = _json.dumps({"ts": "2026-10-02T20:05:00Z", "command": "id",
                            "user": "root", "cwd": "/root",
                            "ssh_client": "10.0.0.9 33111 22", "tty": ""})
        sshd_line = (
            "Oct 02 20:05:01 kali sshd[123]: Accepted publickey for root "
            "from 10.0.0.9 port 33111 ssh2: ED25519 SHA256:unknownfp"
        )
        with patch("app.core.ssh_exec.run_ssh_command") as ssh:
            def fake(cfg, script, timeout):
                if "journalctl" in script:
                    return {"ok": True, "stdout": sshd_line + "\n", "stderr": ""}
                return {"ok": True, "stdout": line + "\n__SIZE__{}".format(len(line + "\n")), "stderr": ""}
            ssh.side_effect = fake
            act.pull_actions(module_db, ws)
        row = module_db.query(models.WorkstationAction).filter(
            models.WorkstationAction.workstation_id == ws.id
        ).first()
        assert row is not None
        assert row.username == "root"  # unknown fingerprint → local user kept
