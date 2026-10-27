"""Command secret redaction + RBAC gating of raw commands, and the
impacket-family parsers (track D follow-up, 2026-10-13).

Contract under test:
- inline secrets in operator commands are masked on every broad surface
  (timeline always; sessions/observations/actions for users without
  credentials.read_secret) and stay raw for the entitled roles;
- ports survive (`-p 445` is a port, `-p S3cret!` is a password);
- impacket-family output parses into identity-only creds drafts — the
  hash/password material never reaches observation payloads.
"""

import pytest
from fastapi.testclient import TestClient

from app import models
from app.core.utils import new_id, ts_now

from ._license_test_utils import license_ee

pytestmark = pytest.mark.ee

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient, module_db):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    undo = license_ee(module_client, module_db)
    r = module_client.post(
        "/api/projects",
        json={"name": "RedactTest", "added": "2026-01-01T00:00:00Z", "status": "active"},
    )
    assert r.status_code == 201, r.text
    _state["pid"] = r.json()["id"]

    # a viewer member: hosts read, NO credentials.read_secret
    viewer = models.User(
        id=new_id("usr"), username="redact_viewer", password_hash="x",
        display_name="v", role="user", created_at=ts_now(),
    )
    module_db.add(viewer)
    module_db.flush()
    module_db.add(models.ProjectMember(
        id=new_id("pm"), project_id=_state["pid"], user_id=viewer.id,
        role="viewer", is_active=True, created_at=ts_now(),
    ))
    # an operator member: has credentials.read_secret
    oper = models.User(
        id=new_id("usr"), username="redact_operator", password_hash="x",
        display_name="o", role="user", created_at=ts_now(),
    )
    module_db.add(oper)
    module_db.flush()
    module_db.add(models.ProjectMember(
        id=new_id("pm"), project_id=_state["pid"], user_id=oper.id,
        role="operator", is_active=True, created_at=ts_now(),
    ))
    module_db.commit()
    _state.update(viewer=viewer, oper=oper)
    yield
    undo()


def _login(c, username):
    # direct password login (created without usable hash — reset via admin API)
    import unittest.mock as mock

    from app.core.security import hash_password

    c.post("/api/auth/logout")
    r = c.post("/api/admin/users")
    # set known passwords through the admin endpoint where available,
    # otherwise patch verify: simplest robust path is a direct DB hash set
    return r


def _login_as(module_db, module_client, user, password):
    user.password_hash = __import__("app.core.security", fromlist=["hash_password"]).hash_password(password)
    module_db.commit()
    module_client.post("/api/auth/logout")
    r = module_client.post("/api/auth/login", json={"username": user.username, "password": password})
    assert r.status_code == 200, r.text


SECRET_CMD = "nxc smb 10.0.0.99 -u admin -p 'Sup3rS3cret!' --local-auth"


# ═══════════════ redaction rules ═══════════════


class TestRedactionRules:
    def test_password_flags_masked_ports_kept(self):
        from app.core.termtrack.redact import redact_command_secrets as r

        assert "-p 445" in r("nmap -sV -p 445 10.0.0.5")
        assert "-p 1-65535" in r("nmap -p 1-65535 10.0.0.5")
        assert "S3cretPass" not in r("hydra -l a -p S3cretPass 10.0.0.5 ssh")
        assert "My Pass123" not in r("nxc smb 10.0.0.5 -u u -p 'My Pass123'")
        assert "S3cretPass" not in r("nxc smb 10.0.0.5 -u u -p S3cretPass --local-auth")

    def test_hashes_and_tokens_masked(self):
        from app.core.termtrack.redact import redact_command_secrets as r

        out = r("impacket-secretsdump -hashes :aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 CORP/a@10.0.0.5")
        assert "aad3b435" not in out and "-hashes" in out
        out2 = r("curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9extsig' https://x.example")
        assert "eyJhbGci" not in out2

    def test_conn_string_and_env(self):
        from app.core.termtrack.redact import redact_command_secrets as r

        out = r("impacket-psexec CORP\\admin:Passw0rd!@10.0.0.5")
        assert "Passw0rd" not in out and "CORP\\admin" in out and "10.0.0.5" in out
        assert "hunter2" not in r("export DB_PASSWORD=hunter2 ./run.sh")

    def test_kerberos_hash(self):
        from app.core.termtrack.redact import redact_command_secrets as r

        line = "hash: $krb5tgs$23$*svc$CORP$MSSQLSvc/x:1433*$a1b2c3"
        out = r(line)
        assert "krb5tgs" not in out or "***REDACTED***" in out


# ═══════════════ timeline masking (everyone) ═══════════════


class TestTimelineMasking:
    def test_timeline_event_masked_for_admin_too(self, module_client: TestClient, module_db):
        # ingest a workstation action with an inline secret through the
        # real ingest path (same as the shell hook uses)
        from app.models.workstation_action import WorkstationAction
        from app.core.workstation.actions import _timeline_event

        ws = models.OperatorWorkstation(
            id=new_id("ows"), project_id=_state["pid"], name="ws-redact",
            provider="docker", status="active",
            meta={"action_log_enabled": True, "action_log_token": "rt-tok"},
            created_at=ts_now(),
        )
        module_db.add(ws)
        module_db.commit()
        action = WorkstationAction(
            id=new_id("wsa"), workstation_id=ws.id, pid=_state["pid"],
            username="op1", command=SECRET_CMD, cwd="/root", ssh_client="",
            tty="/dev/pts/41", source="shell-hook", ts=ts_now(),
        )
        module_db.add(action)
        _timeline_event(module_db, ws, action)
        module_db.commit()
        _state["ws"] = ws

        r = module_client.get("/api/timeline", params={"pid": _state["pid"]})
        assert r.status_code == 200, r.text
        body = r.text
        assert "Sup3rS3cret" not in body
        assert "***REDACTED***" in body


# ═══════════════ RBAC: raw vs masked per role ═══════════════


class TestRoleGating:
    def test_viewer_gets_masked_operator_gets_raw(self, module_client: TestClient, module_db):
        ws = _state["ws"]

        # viewer
        _login_as(module_db, module_client, _state["viewer"], "ViewerPass1!")
        r = module_client.get(f"/api/workstations/{ws.id}/actions")
        assert r.status_code == 200, r.text
        cmds = [a["command"] for a in r.json()["actions"] if a["id"]]
        assert cmds, r.text
        assert all("Sup3rS3cret" not in c for c in cmds)
        assert any("***REDACTED***" in c for c in cmds)

        # operator: entitled to secrets
        _login_as(module_db, module_client, _state["oper"], "OperPass1!")
        r2 = module_client.get(f"/api/workstations/{ws.id}/actions")
        assert r2.status_code == 200
        cmds2 = [a["command"] for a in r2.json()["actions"]]
        assert any("Sup3rS3cret" in c for c in cmds2)

    def test_session_detail_gated(self, module_client: TestClient, module_db):
        from app.models.workstation_session import WorkstationSession

        ws = _state["ws"]
        sess = WorkstationSession(
            id=new_id("wsess"), workstation_id=ws.id, pid=_state["pid"],
            tty="/dev/pts/41", username="op1", state="active",
            started_at=ts_now(), last_event_at=ts_now(), path=[],
        )
        module_db.add(sess)
        module_db.commit()

        _login_as(module_db, module_client, _state["viewer"], "ViewerPass1!")
        r = module_client.get(f"/api/workstations/{ws.id}/sessions/{sess.id}")
        assert r.status_code == 200, r.text
        assert r.json()["commands_redacted"] is True

        _login_as(module_db, module_client, _state["oper"], "OperPass1!")
        r2 = module_client.get(f"/api/workstations/{ws.id}/sessions/{sess.id}")
        assert r2.status_code == 200
        assert r2.json()["commands_redacted"] is False

    def test_observation_provenance_gated(self, module_client: TestClient, module_db):
        from app.core.termtrack import create_observations

        pid, ws = _state["pid"], _state["ws"]
        made = create_observations(
            module_db, pid, ws.id,
            "impacket-psexec CORP\\admin:Passw0rd!@10.10.1.7",
            "[*] Requesting shares\n[!] Launching semi-interactive shell\nC:\\>",
        )
        module_db.commit()
        assert made, "impacket command must produce observations"

        _login_as(module_db, module_client, _state["viewer"], "ViewerPass1!")
        r = module_client.get(f"/api/projects/{pid}/observations")
        assert r.status_code == 200
        assert "Passw0rd" not in r.text

        _login_as(module_db, module_client, _state["oper"], "OperPass1!")
        r2 = module_client.get(f"/api/projects/{pid}/observations")
        assert r2.status_code == 200
        assert "Passw0rd" in r2.text  # provenance keeps the real command


# ═══════════════ impacket parsers ═══════════════


class TestImpacketParsers:
    def test_getuserspns(self):
        from app.core.output_parser import parse_output

        out = (
            "Impacket v0.12.0\n\n"
            "ServicePrincipalName                  Name     MemberOf  PasswordLastSet\n"
            "------------------------------------  -------  --------  ---------------\n"
            "MSSQLSvc/web01.corp.local:1433        svc_web            2025-01-10\n"
            "HTTP/web02.corp.local                 svc_http           2025-03-01\n\n"
            "$krb5tgs$23$*svc_web$CORP.LOCAL$MSSQLSvc~x*$a1b2c3d4$\n"
        )
        r = parse_output("impacket-GetUserSPNs -request", out)
        users = {c["username"] for c in r["creds"]}
        assert {"svc_web", "svc_http"} <= users
        assert all("hash" not in str(c.get("secret", "")) for c in r["creds"])
        assert all("$krb5tgs" not in str(c) for c in r["creds"])

    def test_responder_and_ntlmrelayx(self):
        from app.core.output_parser import parse_output

        r = parse_output(
            "responder -I eth0",
            "[SMB] NTLMv2-SSP Hash     :jbob::CORP:1122334455667788:0101...",
        )
        assert r["creds"] and r["creds"][0]["username"] == "jbob"
        assert "1122334455667788" not in str(r["creds"])

        r2 = parse_output(
            "ntlmrelayx.py -tf targets.txt",
            "[*] Authenticating against 10.1.1.5 as CORP\\svc SUCCEED",
        )
        assert any(c.get("type") == "relay" for c in r2["creds"])

    def test_secrets_no_secret_material_in_observations(self, module_db):
        from app.core.termtrack import create_observations

        made = create_observations(
            module_db, _state["pid"], _state["ws"].id,
            "impacket-psexec CORP\\admin:Passw0rd!@10.10.1.9",
            "[!] Launching semi-interactive shell\nC:\\>",
        )
        module_db.commit()
        payload = str([(o.kind, o.data) for o in made])
        assert "Passw0rd" not in payload
        assert any(o.kind == "access_context" and o.data.get("username") == "admin" for o in made)
        assert any(o.kind == "host" and o.data.get("ip") == "10.10.1.9" for o in made)
