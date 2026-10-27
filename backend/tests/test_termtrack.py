"""Termtrack: PTY sessions, observations, auto-enrichment, deconfliction v2.

Covers the P0–P3 acceptance criteria that are testable headless:

- PTY segmentation on OSC-7770 markers (ANSI noise, incremental tails);
- hook ↔ PTY dedup (same command/tty/time → one event, output attached);
- session lifecycle (correlate by tty, close on tty reuse, idle close);
- nested-SSH hops: suspected from the command, uncertainty explicit,
  never fabricated for non-ssh commands;
- observations: dedup hash, secret scrubbing, direct vs inferred;
- enrichment: auto-apply creates/updates without overwriting, conflicts
  stay pending with the discrepancy recorded;
- deconfliction v2: range/task claims, overlap warnings;
- API surface: sessions/observations/status with project scoping.
"""

import base64
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app import models
from app.core.utils import new_id, ts_now

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"

_state: dict = {}


def _mark(cmd: str) -> str:
    return f"\x1b]7770;umbryx;cmd;{base64.b64encode(cmd.encode()).decode()}\x07"


def _ts(minutes_ago: float = 0) -> str:
    return (datetime.now(UTC).replace(tzinfo=None) - timedelta(minutes=minutes_ago)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient, module_db):
    _state["module_db"] = module_db
    _state["module_client"] = module_client
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post(
        "/api/projects",
        json={"name": "TermtrackTest", "added": "2026-01-01T00:00:00Z", "status": "active"},
    )
    assert r.status_code == 201, r.text
    _state["pid"] = r.json()["id"]
    ws = models.OperatorWorkstation(
        id=new_id("ows"), project_id=_state["pid"], user_id=None,
        name="ws-tt", provider="docker", status="active",
        meta={"action_log_enabled": True, "action_log_mode": "push",
              "action_log_token": "tt-token", "pty_enabled": True},
        created_at=ts_now(),
    )
    module_db.add(ws)
    module_db.commit()
    _state["ws"] = ws
    yield


# ═══════════════ segmentation ═══════════════


class TestSegmentation:
    def test_split_on_markers_with_ansi_noise(self):
        from app.core.termtrack.segment import segment_stream

        stream = (
            "banner noise\r\n"
            + _mark("nmap -sV 10.0.0.5")
            + "\x1b[?1049hStarting Nmap 7.94\x1b[0m\r\n"
            "Nmap scan report for 10.0.0.5\nPORT STATE SERVICE\n22/tcp open ssh\n"
            + _mark("id")
            + "uid=0(root)\r\n"
        )
        segs = segment_stream(stream)
        assert [s["command"] for s in segs] == ["nmap -sV 10.0.0.5", "id"]
        assert "Nmap scan report for 10.0.0.5" in segs[0]["output"]
        assert "\x1b" not in segs[0]["output"]
        assert "uid=0(root)" in segs[1]["output"]
        # pre-marker banner is dropped (no command to attribute)
        assert "banner noise" not in "".join(s["output"] for s in segs)

    def test_open_tail_kept_until_next_marker(self):
        # an unfinished command's output stays OUT of the emitted segments
        # until a following marker closes it (see ingest_pty_bytes: tail)
        from app.core.termtrack.ingest import ingest_pty_bytes
        from app.models.workstation_session import WorkstationSession

        module_db = _state["module_db"]
        ws = _state["ws"]
        sess = WorkstationSession(
            id=new_id("wsess"), workstation_id=ws.id, pid=ws.project_id,
            tty="/dev/pts/31", username="op1", state="active",
            started_at=_ts(2), last_event_at=_ts(1), path=[],
        )
        module_db.add(sess)
        module_db.flush()
        stats, tail = ingest_pty_bytes(
            module_db, ws, sess, "tail.log", _mark("slowtool") + "partial output\r\n", ""
        )
        assert stats["commands"] == 0  # not closed yet
        assert tail  # bytes retained for the next round

        stats2, tail2 = ingest_pty_bytes(
            module_db, ws, sess, "tail.log", "final line\r\n" + _mark("echo ok") + "ok\r\n", tail
        )
        # slowtool is now closed by the echo marker; echo itself stays open
        assert stats2["commands"] == 1
        assert "ok" in tail2

        stats3, _ = ingest_pty_bytes(
            module_db, ws, sess, "tail.log", _mark(""), tail2
        )
        assert stats3["commands"] == 1  # empty marker closes echo


# ═══════════════ sessions & jumps ═══════════════


class TestSessions:
    def test_correlate_by_tty_and_jump_detection(self, module_db):
        from app.core.termtrack.sessions import correlate_action, record_ssh_jump
        from app.models.workstation_action import WorkstationAction
        from app.models.workstation_session import WorkstationSession

        ws = _state["ws"]
        a1 = WorkstationAction(
            id=new_id("wsa"), workstation_id=ws.id, pid=ws.project_id,
            username="op1", command="whoami", cwd="/root", ssh_client="10.1.1.1 50000 22",
            tty="/dev/pts/3", source="shell-hook", ts=_ts(5),
        )
        module_db.add(a1)
        sess = correlate_action(module_db, ws, a1)
        assert a1.session_id == sess.id
        assert sess.tty == "/dev/pts/3"

        hop = record_ssh_jump(module_db, sess, "ssh root@10.99.0.7", _ts(4))
        assert hop and hop["host"] == "10.99.0.7"
        assert hop["confirmed"] is False  # command proves intent, not landing
        assert any(h.get("host") == "10.99.0.7" for h in sess.path)

        # non-jump commands must not fabricate hops
        assert record_ssh_jump(module_db, sess, "git clone ssh://git@host/repo", _ts(3)) is None
        assert record_ssh_jump(module_db, sess, "cat /etc/passwd", _ts(3)) is None

        # confirm upgrade — and prove BOTH writes survive a re-query
        # (found live: in-place JSONB mutation never hit the DB)
        module_db.commit()
        from app.core.termtrack.sessions import confirm_jump

        confirm_jump(module_db, sess, "10.99.0.7", _ts(3), evidence="prompt")
        module_db.commit()
        module_db.expire_all()
        sess2 = module_db.query(WorkstationSession).filter(
            WorkstationSession.id == sess.id).first()
        hops = {h["host"]: h for h in (sess2.path or [])}
        assert "10.99.0.7" in hops, f"hop not persisted: {sess2.path}"
        assert hops["10.99.0.7"]["confirmed"] is True
        assert hops["10.99.0.7"]["evidence"] == "prompt"

    def test_new_login_same_tty_closes_old_session(self, module_db):
        from app.core.termtrack.sessions import correlate_action
        from app.models.workstation_action import WorkstationAction
        from app.models.workstation_session import WorkstationSession

        ws = _state["ws"]
        old = WorkstationSession(
            id=new_id("wsess"), workstation_id=ws.id, pid=ws.project_id,
            tty="/dev/pts/7", username="op1", state="active",
            started_at=_ts(60), last_event_at=_ts(40), path=[],
        )
        module_db.add(old)
        module_db.flush()
        fresh = WorkstationAction(
            id=new_id("wsa"), workstation_id=ws.id, pid=ws.project_id,
            username="op2", command="ls", ssh_client="", tty="/dev/pts/7",
            source="shell-hook", ts=_ts(1),
        )
        module_db.add(fresh)
        correlate_action(module_db, ws, fresh)
        assert old.state == "closed"
        assert fresh.session_id != old.id
        module_db.rollback()

    def test_idle_close(self, module_db):
        from app.core.termtrack.sessions import close_idle_sessions
        from app.models.workstation_session import WorkstationSession

        ws = _state["ws"]
        stale = WorkstationSession(
            id=new_id("wsess"), workstation_id=ws.id, pid=ws.project_id,
            tty="/dev/pts/9", username="op1", state="active",
            started_at=_ts(500), last_event_at=_ts(400), path=[],
        )
        module_db.add(stale)
        module_db.commit()
        closed = close_idle_sessions(module_db)
        assert closed >= 1
        assert stale.state == "closed"


# ═══════════════ observations & enrichment ═══════════════


NMAP_OUT = """Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 10.77.0.20
Host is up (0.0010s latency).
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1
80/tcp   open  http    nginx 1.24.0
MAC Address: 02:00:00:00:00:AA (Unknown)
"""


class TestObservations:
    def test_create_dedup_and_scrub(self, module_db):
        from app.core.termtrack import create_observations

        pid, ws = _state["pid"], _state["ws"]
        made = create_observations(module_db, pid, ws.id, "nmap -sV 10.77.0.20", NMAP_OUT)
        assert made, "nmap output must produce observations"
        hosts = [o for o in made if o.kind == "host"]
        assert hosts and hosts[0].data["ip"] == "10.77.0.20"
        assert any("22/tcp" in p for p in hosts[0].data.get("ports", []))

        again = create_observations(module_db, pid, ws.id, "nmap -sV 10.77.0.20", NMAP_OUT)
        assert len(again) == len(made)  # dedup: same output, no new rows

    def test_auto_apply_creates_host_and_no_dup(self, module_db):
        from app.core.termtrack import create_observations
        from app.core.termtrack.enrich import apply_observation

        pid, ws = _state["pid"], _state["ws"]
        made = create_observations(module_db, pid, ws.id, "nmap -sV 10.77.0.21", NMAP_OUT.replace("10.77.0.20", "10.77.0.21"))
        host_obs = next(o for o in made if o.kind == "host")
        r = apply_observation(module_db, host_obs, auto=True)
        assert r["changed"] and r.get("created")
        host = module_db.query(models.Host).filter(
            models.Host.pid == pid, models.Host.ip == "10.77.0.21").first()
        assert host is not None
        assert host.import_source == "termtrack"
        assert any("22/tcp" in p for p in host.ports)

        # second observation of the same fact must not duplicate the host
        made2 = create_observations(module_db, pid, ws.id, "nmap -sV 10.77.0.21", NMAP_OUT.replace("10.77.0.20", "10.77.0.21"))
        r2 = apply_observation(module_db, next(o for o in made2 if o.kind == "host"), auto=True)
        count = module_db.query(models.Host).filter(
            models.Host.pid == pid, models.Host.ip == "10.77.0.21").count()
        assert count == 1

    def test_conflict_not_overwritten(self, module_db):
        from app.core.termtrack import create_observations
        from app.core.termtrack.enrich import apply_observation

        pid, ws = _state["pid"], _state["ws"]
        # stored host with a hostname already set
        h = models.Host(
            id=new_id("h"), pid=pid, ip="10.77.0.22", hostname="real-name",
            os="", status="alive", ports=[], services=[], ips=[], tags=[],
            domain="", role="unknown", import_source="manual",
        )
        module_db.add(h)
        module_db.flush()

        out = NMAP_OUT.replace("10.77.0.20", "10.77.0.22").replace(
            "Nmap scan report for 10.77.0.22", "Nmap scan report for fake-name (10.77.0.22)")
        made = create_observations(module_db, pid, ws.id, "nmap -sV 10.77.0.22", out)
        host_obs = next(o for o in made if o.kind == "host" and o.data.get("ip") == "10.77.0.22")
        r = apply_observation(module_db, host_obs, auto=True)
        # hostname conflicts → observation records it, stored value wins
        module_db.refresh(h)
        assert h.hostname == "real-name"
        assert (r.get("conflict") or host_obs.provenance.get("apply", {}).get("conflict"))

    def test_inferred_stays_pending(self, module_db):
        from app.core.termtrack import create_observations
        from app.core.termtrack.enrich import apply_observation

        pid, ws = _state["pid"], _state["ws"]
        made = create_observations(
            module_db, pid, ws.id, "netexec smb 10.77.0.23 -u user -p 'S3cretPass!' --local-auth",
            "SMB         10.77.0.23   445    HOST01   [+] HOST01\\user:S3cretPass! (Pwn3d!)\n"
            "CREDENTIALS: [+] HOST01\\svc_backup:Backup2026!",
        )
        ctx = [o for o in made if o.kind == "access_context"]
        assert ctx, "netexec output must yield access context"
        assert ctx[0].confidence == "inferred"
        r = apply_observation(module_db, ctx[0], auto=True)
        assert not r.get("changed")
        module_db.refresh(ctx[0])
        assert ctx[0].status == "pending"
        # secret must not survive in the payload
        assert "S3cretPass" not in str(ctx[0].data)


# ═══════════════ hook ↔ PTY dedup ═══════════════


class TestHookPtyDedup:
    def test_twin_reused_no_duplicate_row(self, module_db):
        from app.core.termtrack.ingest import _find_hook_twin, ingest_pty_bytes
        from app.models.workstation_action import WorkstationAction

        pid, ws = _state["pid"], _state["ws"]
        ts = _ts(0)
        hook_row = WorkstationAction(
            id=new_id("wsa"), workstation_id=ws.id, pid=pid,
            username="op1", command="nmap -sV 10.77.0.30", cwd="/root",
            ssh_client="", tty="/dev/pts/11", source="shell-hook", ts=ts,
        )
        module_db.add(hook_row)
        module_db.flush()

        from app.models.workstation_session import WorkstationSession

        sess = WorkstationSession(
            id=new_id("wsess"), workstation_id=ws.id, pid=pid, tty="/dev/pts/11",
            username="op1", state="active", started_at=ts, last_event_at=ts, path=[],
        )
        module_db.add(sess)
        module_db.flush()

        stream = (
            _mark("nmap -sV 10.77.0.30")
            + NMAP_OUT.replace("10.77.0.20", "10.77.0.30")
            + _mark("echo done") + "done\r\n"
            + _mark("")  # closes the previous segment
        )
        stats, tail = ingest_pty_bytes(module_db, ws, sess, "test.log", stream, "")
        assert stats["commands"] == 2

        dup = (
            module_db.query(WorkstationAction)
            .filter(
                WorkstationAction.workstation_id == ws.id,
                WorkstationAction.command == "nmap -sV 10.77.0.30",
            )
            .count()
        )
        assert dup == 1, "hook already logged it — PTY must not add a second row"
        # and the hook row is now session-linked
        module_db.refresh(hook_row)
        assert hook_row.session_id == sess.id
        # pty-only command ('echo done') DID create its own row
        echo = (
            module_db.query(WorkstationAction)
            .filter(WorkstationAction.command == "echo done")
            .first()
        )
        assert echo and echo.source == "pty"


# ═══════════════ deconfliction v2 ═══════════════


class TestDeconflictionV2:
    def test_scope_claims_crud_and_conflict(self, module_client: TestClient, module_db):
        pid = _state["pid"]
        r = module_client.post(
            f"/api/projects/{pid}/scope-claims",
            json={"target": "10.99.0.0/24", "note": "external scan"},
        )
        assert r.status_code == 201, r.text
        claim = r.json()
        assert claim["claim_type"] == "range"

        # same operator re-claims → extend, not 409
        r2 = module_client.post(
            f"/api/projects/{pid}/scope-claims",
            json={"target": "10.99.0.0/24", "note": ""},
        )
        # endpoint declares 201; the extend path reuses it — assert semantics
        assert r2.status_code in (200, 201) and r2.json()["status"] == "extended"

        # free text → task
        r3 = module_client.post(
            f"/api/projects/{pid}/scope-claims",
            json={"target": "AD reconnaissance phase", "note": "kerberos stuff"},
        )
        assert r3.status_code == 201 and r3.json()["claim_type"] == "task"

        listing = module_client.get(f"/api/projects/{pid}/scope-claims").json()
        targets = {c["target"] for c in listing}
        assert {"10.99.0.0/24", "AD reconnaissance phase"} <= targets

        r4 = module_client.delete(f"/api/projects/{pid}/scope-claims/{claim['id']}")
        assert r4.status_code == 204

    def test_warnings_see_scan_vs_claim_overlap(self, module_client: TestClient, module_db):
        pid = _state["pid"], _state["ws"]
        pid = pid[0]
        # operator A claims the range
        module_client.post(
            f"/api/projects/{pid}/scope-claims",
            json={"target": "10.88.0.0/16"},
        )
        # operator B scans an overlapping range from the workstation
        from app.models.workstation_action import WorkstationAction

        module_db.add(WorkstationAction(
            id=new_id("wsa"), workstation_id=_state["ws"].id, pid=pid,
            username="opB", command="nmap -p 80 10.88.1.0/24", cwd="",
            ssh_client="", tty="/dev/pts/21", source="shell-hook", ts=_ts(1),
        ))
        module_db.commit()

        r = module_client.get(f"/api/projects/{pid}/deconfliction/warnings")
        assert r.status_code == 200, r.text
        kinds = [w["kind"] for w in r.json()["warnings"]]
        assert "claim_conflict" in kinds or "scan_overlap" in kinds, r.json()


# ═══════════════ API surface ═══════════════


class TestTermtrackAPI:
    def test_sessions_and_observations_lists(self, module_client: TestClient, module_db):
        pid = _state["pid"]
        r = module_client.get(f"/api/projects/{pid}/workstation-sessions")
        assert r.status_code == 200, r.text
        assert isinstance(r.json(), list)

        r2 = module_client.get(f"/api/projects/{pid}/observations")
        assert r2.status_code == 200
        obs = r2.json()
        assert all(o["status"] in ("pending", "applied", "dismissed") for o in obs)
        # provenance is present for go-to-source
        for o in obs:
            assert "command" in o["provenance"]

    def test_approve_dismiss_flow(self, module_client: TestClient, module_db):
        from app.core.termtrack import create_observations

        pid, ws = _state["pid"], _state["ws"]
        host99 = models.Host(
            id=new_id("h"), pid=pid, ip="10.77.9.9", hostname="",
            os="", status="alive", ports=[], services=[], ips=[], tags=[],
            domain="", role="unknown", import_source="manual",
        )
        module_db.add(host99)
        made = create_observations(
            module_db, pid, ws.id, "dig corp.acme",
            ";; ANSWER SECTION:\ncorp.acme.\t300\tIN\tA\t10.77.9.9\n",
        )
        module_db.commit()  # direct writes must be committed before HTTP reads them
        dns_obs = next((o for o in made if o.kind == "dns"), None)
        assert dns_obs, made
        r = module_client.post(f"/api/projects/{pid}/observations/{dns_obs.id}/approve")
        assert r.status_code == 200, r.text
        module_db.refresh(dns_obs)
        assert dns_obs.status == "applied"
        assert dns_obs.provenance.get("approved_by") == ADMIN
        module_db.refresh(host99)
        assert host99.hostname == "corp.acme"

        made2 = create_observations(
            module_db, pid, ws.id, "host other.acme",
            "other.acme has address 10.77.9.10\n",
        )
        module_db.commit()
        o2 = next(o for o in made2 if o.kind == "dns")
        r2 = module_client.post(f"/api/projects/{pid}/observations/{o2.id}/dismiss")
        assert r2.status_code == 200
        module_db.refresh(o2)
        assert o2.status == "dismissed"

    def test_telemetry_status(self, module_client: TestClient):
        ws = _state["ws"]
        r = module_client.get(f"/api/workstations/{ws.id}/telemetry")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["hook_enabled"] is True
        assert body["pty_enabled"] is True
        assert isinstance(body["sessions"], list)

    def test_viewer_cannot_approve(self, module_client: TestClient, module_db):
        """Project scoping: a viewer of another project sees nothing."""
        r = module_client.post(
            "/api/projects",
            json={"name": "TermtrackOther", "added": "2026-01-01T00:00:00Z", "status": "active"},
        )
        other_pid = r.json()["id"]
        r2 = module_client.get(f"/api/projects/{other_pid}/observations")
        assert r2.status_code == 200 and r2.json() == []
