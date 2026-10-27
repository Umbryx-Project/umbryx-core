"""Continuous attack-surface monitoring (SurfaceWatch).

Pins: state capture/diff semantics, CRUD + manual-run endpoints, the
due-fire scheduler logic (interval + running guard + HA claim), and one
full mocked run — nmap result parsed through the real scan pipeline,
hosts upserted, surface growth notified to project members and written
to the timeline.
"""

from datetime import UTC
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.core.surface_monitor import (
    _run_watch_sync,
    diff_has_changes,
    diff_states,
    fire_due_watches,
)
from app.core.utils import new_id, ts_now
from app.models import Host
from app.models.surface_watch import SurfaceWatch

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"

_state: dict = {}

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
<host><status state="up"/>
<address addr="198.51.100.50" addrtype="ipv4"/>
<hostnames><hostname name="newbox.example"/></hostnames>
<ports><port protocol="tcp" portid="443"><state state="open"/>
<service name="https"/></port></ports></host>
</nmaprun>"""


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    yield


def _make_project(client, name="WatchProj"):
    r = client.post(
        "/api/projects", json={"name": f"{name}{new_id('w')[:6]}", "added": "2025-01-01T00:00:00Z"}
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


class TestDiff:
    def test_new_host_and_port(self):
        pre = {"10.0.0.1": {"hostname": "a", "status": "up", "ports": ["22/tcp"], "services": []}}
        post = {
            "10.0.0.1": {"hostname": "a", "status": "up", "ports": ["22/tcp", "443/tcp"], "services": ["https"]},
            "10.0.0.9": {"hostname": "b", "status": "up", "ports": ["445/tcp"], "services": []},
        }
        d = diff_states(pre, post)
        assert [h["ip"] for h in d["new_hosts"]] == ["10.0.0.9"]
        assert d["new_ports"] == [{"ip": "10.0.0.1", "ports": ["443/tcp"]}]
        assert d["new_services"] == [{"ip": "10.0.0.1", "services": ["https"]}]
        assert diff_has_changes(d)

    def test_no_growth_no_alert(self):
        pre = {"10.0.0.1": {"hostname": "a", "status": "up", "ports": ["22/tcp"], "services": []}}
        post = {"10.0.0.1": {"hostname": "renamed", "status": "up", "ports": ["22/tcp"], "services": []}}
        d = diff_states(pre, post)
        assert not diff_has_changes(d)
        assert d["status_changes"] == []


class TestCrud:
    def test_crud_flow(self, module_client):
        pid = _make_project(module_client)
        _state["pid"] = pid

        r = module_client.post(
            f"/api/projects/{pid}/watch",
            json={"name": "perimeter", "interval_minutes": 30, "targets": "198.51.100.0/24"},
        )
        assert r.status_code == 201, r.text
        w = r.json()
        assert w["interval_minutes"] == 30
        assert w["enabled"] is True
        _state["wid"] = w["id"]

        r = module_client.get(f"/api/projects/{pid}/watch")
        assert any(x["id"] == _state["wid"] for x in r.json())

        r = module_client.patch(
            f"/api/projects/{pid}/watch/{_state['wid']}", json={"enabled": False}
        )
        assert r.json()["enabled"] is False

        r = module_client.delete(f"/api/projects/{pid}/watch/{_state['wid']}")
        assert r.status_code == 204

    def test_manual_run_202(self, module_client):
        r = module_client.post(
            f"/api/projects/{_state['pid']}/watch",
            json={"interval_minutes": 60, "targets": "198.51.100.0/24"},
        )
        wid = r.json()["id"]
        _state["wid2"] = wid
        r = module_client.post(f"/api/projects/{_state['pid']}/watch/{wid}/run")
        assert r.status_code == 202
        module_client.delete(f"/api/projects/{_state['pid']}/watch/{wid}")


class TestFireDue:
    def test_interval_respected(self, module_client, module_db):
        pid = _make_project(module_client)
        w = SurfaceWatch(
            id=new_id("sw"), pid=pid, name="t", interval_minutes=60,
            targets="198.51.100.0/24", created_at=ts_now(),
            last_run_at=ts_now(),  # just ran
        )
        module_db.add(w)
        module_db.commit()

        now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
        with patch("app.core.surface_monitor.threading.Thread") as TH:
            assert fire_due_watches(module_db, now) == 0
            TH.assert_not_called()

    def test_due_fires_once_and_claims(self, module_client, module_db):
        from datetime import datetime

        pid = _make_project(module_client)
        w = SurfaceWatch(
            id=new_id("sw"), pid=pid, name="t2", interval_minutes=5,
            targets="198.51.100.0/24", created_at=ts_now(),
        )
        module_db.add(w)
        module_db.commit()

        now = datetime.now(UTC)
        with patch("app.core.surface_monitor.threading.Thread") as TH:
            assert fire_due_watches(module_db, now) == 1
            assert TH.call_count == 1
            module_db.expire(w)
            assert w.state == "running"
            # second instance tick: claimed, not fired again
            assert fire_due_watches(module_db, now) == 0
        module_db.query(SurfaceWatch).filter(SurfaceWatch.id == w.id).delete()
        module_db.commit()


class TestFullRun:
    def test_run_upserts_notifies_and_diffs(self, module_client, module_db):
        from app.models.notification import Notification

        pid = _make_project(module_client, "WatchRun")
        w = SurfaceWatch(
            id=new_id("sw"), pid=pid, name="perim", interval_minutes=60,
            targets="198.51.100.0/24", created_at=ts_now(),
        )
        module_db.add(w)
        module_db.commit()
        _state["run_pid"] = pid

        def fake_ssh(cfg, cmd, timeout):
            return {"stdout": NMAP_XML, "stderr": "", "rc": 0}

        with (
            patch("app.core.attacker_transport.resolve_scan_target", return_value={}),
            patch("app.core.ssh_exec.run_ssh_command", side_effect=fake_ssh),
            patch("app.core.job_tracker.start_job") as sj,
        ):
            sj.return_value = MagicMock(id="job_x")
            # membership for push_to_project_members: admin is a member via owner add
            _run_watch_sync(w.id)

        module_db.expire_all()
        row = module_db.query(SurfaceWatch).get(w.id)
        assert row.state == "idle"
        assert row.last_job_id == "job_x"
        ips = [h["ip"] for h in row.last_diff_json.get("new_hosts", [])]
        assert "198.51.100.50" in ips, "newly discovered host must land in the diff"
        assert "198.51.100.50" in row.baseline_json

        host = module_db.query(Host).filter(
            Host.pid == pid, Host.ip == "198.51.100.50"
        ).first()
        assert host is not None, "scan pipeline must upsert the host"
        assert "443/tcp" in (host.ports or [])

        notes = module_db.query(Notification).filter(
            Notification.project_id == pid,
            Notification.title.ilike("%surface changed%"),
        ).all()
        assert notes, "project members must be notified about surface growth"
        assert all("198.51.100.50" in (n.body or "") for n in notes)
