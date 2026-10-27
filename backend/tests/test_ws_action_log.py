"""Workstation action logging — hook ingest, token auth, deconfliction feed."""

import pytest
from fastapi.testclient import TestClient

from app.core.utils import new_id, ts_now
from app.models import Host
from app.models.workstation_action import WorkstationAction
from app.core.workstation.actions import extract_target_ips
from tests.test_deconfliction import _make_project_with_host  # noqa: F401 — reuse

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    yield


def _make_ws(db, pid):
    from app.models import OperatorWorkstation

    ws = OperatorWorkstation(
        id=new_id("ws"),
        project_id=pid,
        name="kali-1",
        status="ready",
        provider="docker",
        created_at=ts_now(),
        meta={"action_log_token": "tok123", "action_log_enabled": True},
    )
    db.add(ws)
    db.commit()
    return ws


class TestExtractIps:
    def test_extracts_exact_ips_only(self):
        cmd = "nmap -sV 10.0.0.5 && crackmapexec smb 10.0.0.6 -u u --扫描 10.0.0.0/24"
        assert extract_target_ips(cmd) == {"10.0.0.5", "10.0.0.6"}

    def test_cidr_ignored(self):
        assert extract_target_ips("nmap 192.168.0.0/24") == set()
        assert extract_target_ips("smbclient //10.1.2.3/share") == {"10.1.2.3"}


class TestIngest:
    def test_token_auth_and_persist(self, module_client, module_db):
        from tests.test_deconfliction import _make_project_with_host

        pid, hid, ip = _make_project_with_host(module_client, module_db, ip="198.51.100.70")
        ws = _make_ws(module_db, pid)
        _state.update(pid=pid, hid=hid, ip=ip, ws=ws)

        url = f"/api/workstations/ws-actions/{ws.id}"
        # no token
        r = module_client.post(url, json={"command": "id", "user": "root"})
        assert r.status_code == 401
        # wrong token
        r = module_client.post(url, json={"command": "id"}, headers={"Authorization": "Bearer nope"})
        assert r.status_code == 401

        r = module_client.post(
            url,
            json={"command": f"nmap -sV {ip}", "user": "root", "cwd": "/root"},
            headers={"Authorization": "Bearer tok123"},
        )
        assert r.status_code == 200, r.text

        rows = (
            module_db.query(WorkstationAction)
            .filter(WorkstationAction.workstation_id == ws.id)
            .all()
        )
        assert len(rows) == 1
        assert "nmap" in rows[0].command
        assert rows[0].pid == pid

        # timeline event written
        from app.models import TimelineEvent

        evts = (
            module_db.query(TimelineEvent)
            .filter(TimelineEvent.pid == pid, TimelineEvent.entity == "workstation")
            .all()
        )
        assert any("nmap" in e.label for e in evts)

    def test_disabled_ws_rejects(self, module_client, module_db):
        ws = _state["ws"]
        ws.meta = {**ws.meta, "action_log_enabled": False}
        module_db.commit()
        r = module_client.post(
            f"/api/workstations/ws-actions/{ws.id}",
            json={"command": "id"},
            headers={"Authorization": "Bearer tok123"},
        )
        assert r.status_code == 403
        ws.meta = {**ws.meta, "action_log_enabled": True}
        module_db.commit()


class TestDeconflictionFeed:
    def test_ws_source_in_engagement_map(self, module_client, module_db):
        pid, hid, ip = _state["pid"], _state["hid"], _state["ip"]
        # simulate a recent shell action against the host
        module_db.add(
            WorkstationAction(
                id=new_id("wsa"),
                workstation_id=_state["ws"].id,
                pid=pid,
                username="root",
                command=f"netexec smb {ip} -u users.txt",
                cwd="/root",
                ts=ts_now(),
            )
        )
        module_db.commit()

        r = module_client.get(f"/api/projects/{pid}/deconfliction")
        assert r.status_code == 200
        entry = r.json()["engagement"].get(hid)
        assert entry, "host with recent workstation activity must appear in the map"
        src = next(o for o in entry["operators"] if "ws" in o["sources"])
        assert src["workstation"] == "kali-1"
        assert src["since"]


class TestEngagementBroadcast:
    """Shell activity engages a host automatically, so it must be announced.

    Nothing was broadcast when an action landed, so the map chip and the host
    panel only picked the engagement up on their next 30s poll — which looks
    like "it only appears after reloading the page".
    """

    def test_ingest_broadcasts_for_a_targeted_project_host(
        self, module_client: TestClient, module_db, monkeypatch
    ):
        pid, hid, ip = _make_project_with_host(module_client, module_db, ip="198.51.100.90")
        ws = _make_ws(module_db, pid)
        sent = []
        monkeypatch.setattr(
            "app.core.events.bcast",
            lambda p, entity, action, payload: sent.append((p, entity, action, payload)),
        )

        from app.core.workstation.actions import ingest_action

        ingest_action(module_db, ws, {"user": "admin", "command": f"nmap -sV {ip}"})

        match = [s for s in sent if s[1:3] == ("host", "engagement")]
        assert match, f"no engagement broadcast, got {[s[1:3] for s in sent]}"
        p, _e, _a, payload = match[0]
        assert p == pid
        assert payload["host_ids"] == [hid]
        assert payload["workstation_id"] == ws.id

    def test_no_broadcast_when_the_command_targets_nothing_known(
        self, module_client: TestClient, module_db, monkeypatch
    ):
        pid, _hid, _ip = _make_project_with_host(module_client, module_db, ip="198.51.100.91")
        ws = _make_ws(module_db, pid)
        sent = []
        monkeypatch.setattr(
            "app.core.events.bcast",
            lambda p, entity, action, payload: sent.append((p, entity, action, payload)),
        )

        from app.core.workstation.actions import ingest_action

        ingest_action(module_db, ws, {"user": "admin", "command": "ls -la /tmp"})
        ingest_action(module_db, ws, {"user": "admin", "command": "nmap 203.0.113.9"})

        assert [s for s in sent if s[1:3] == ("host", "engagement")] == []

    def test_a_failing_broadcast_does_not_break_the_action_log(
        self, module_client: TestClient, module_db, monkeypatch
    ):
        pid, _hid, ip = _make_project_with_host(module_client, module_db, ip="198.51.100.92")
        ws = _make_ws(module_db, pid)

        def boom(*_a, **_kw):
            raise RuntimeError("socket down")

        monkeypatch.setattr("app.core.events.bcast", boom)

        from app.core.workstation.actions import ingest_action

        action = ingest_action(module_db, ws, {"user": "admin", "command": f"nmap {ip}"})
        assert action.id
        assert (
            module_db.query(WorkstationAction).filter(WorkstationAction.id == action.id).first()
            is not None
        )
