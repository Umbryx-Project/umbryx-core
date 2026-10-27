"""Tests for sync API — push, pull, status, conflict resolution, policy."""
import hashlib
import hmac
import json
import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app import models
from app.core.utils import new_id

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
TS = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
SYNC_KEY = "test-sync-key"

_state: dict = {}


def _sign(payload: dict) -> str:
    payload_str = json.dumps(payload, sort_keys=True)
    return "sha256=" + hmac.new(SYNC_KEY.encode(), payload_str.encode(), hashlib.sha256).hexdigest()


def _signed_event(ev: dict, pid: str = "") -> dict:
    from app.routers.sync_api import event_envelope, sign_event as _server_sign

    ev = dict(ev)
    payload_str = json.dumps(ev.get("payload", {}), sort_keys=True)
    if not ev.get("signature"):
        ev["signature"] = _server_sign(
            event_envelope(
                pid,
                ev.get("instance_id", ""),
                ev.get("seq", 0),
                ev.get("entity_type", ""),
                ev.get("entity_id", ""),
                ev.get("op", ""),
                payload_str,
            )
        )
    if not ev.get("payload_hash"):
        ev["payload_hash"] = hashlib.sha256(payload_str.encode()).hexdigest()
    return ev


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient, module_db: Session):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    r = module_client.post("/api/projects", json={"name": "SyncTest", "added": TS, "status": "active"})
    assert r.status_code == 201
    _state["pid"] = r.json()["id"]
    yield
    module_client.post("/api/auth/logout")


class TestSyncPush:
    def test_push_applies_events(self, module_client: TestClient, module_db: Session):
        pid = _state["pid"]
        events = [
            _signed_event({
                "instance_id": "inst-001",
                "seq": 1,
                "entity_type": "finding",
                "entity_id": "f-001",
                "op": "create",
                "payload": {"title": "test finding"},
                "payload_hash": "",
                "signature": "",
            }, pid)
        ]
        r = module_client.post("/api/sync/push", json={"pid": pid, "events": events})
        assert r.status_code == 200
        data = r.json()
        assert data["applied"] == 1
        assert data["conflicts"] == 0

        evt = module_db.query(models.SyncEvent).filter(models.SyncEvent.instance_id == "inst-001").first()
        assert evt is not None
        assert evt.seq == 1

        state = module_db.query(models.SyncState).filter(models.SyncState.instance_id == "inst-001").first()
        assert state is not None
        assert state.remote_version == 1

    def test_push_rejects_replay(self, module_client: TestClient, module_db: Session):
        pid = _state["pid"]
        events_v1 = [
            _signed_event({
                "instance_id": "inst-002",
                "seq": 1,
                "entity_type": "host",
                "entity_id": "h-001",
                "op": "create",
                "payload": {},
                "payload_hash": "",
                "signature": "",
            }, pid)
        ]
        r = module_client.post("/api/sync/push", json={"pid": pid, "events": events_v1})
        assert r.status_code == 200
        assert r.json()["applied"] == 1

        replay = [
            _signed_event({
                "instance_id": "inst-002",
                "seq": 1,
                "entity_type": "host",
                "entity_id": "h-001",
                "op": "update",
                "payload": {"malicious": True},
                "payload_hash": "",
                "signature": "",
            }, pid)
        ]
        r = module_client.post("/api/sync/push", json={"pid": pid, "events": replay})
        assert r.status_code == 200
        assert r.json()["applied"] == 0

    def test_push_rejects_hash_mismatch(self, module_client: TestClient, module_db: Session):
        pid = _state["pid"]
        events = [
            _signed_event({
                "instance_id": "inst-003",
                "seq": 1,
                "entity_type": "note",
                "entity_id": "n-001",
                "op": "create",
                "payload": {"content": "real"},
                "payload_hash": "badhash",
                "signature": "",
            }, pid)
        ]
        r = module_client.post("/api/sync/push", json={"pid": pid, "events": events})
        assert r.status_code == 200
        assert r.json()["applied"] == 0

    def test_push_rejects_cross_project_retarget(self, module_client: TestClient, module_db: Session):
        """Security audit 2026-10-07 (finding 4): an event validly signed for
        one project must not be applicable to another project's pid."""
        pid = _state["pid"]
        r = module_client.post(
            "/api/projects", json={"name": "SyncTestOther", "added": TS, "status": "active"}
        )
        assert r.status_code == 201
        other_pid = r.json()["id"]
        events = [
            _signed_event({
                "instance_id": "inst-retarget",
                "seq": 1,
                "entity_type": "note",
                "entity_id": "n-retarget",
                "op": "create",
                "payload": {"content": "signed for pid, pushed to other_pid"},
                "payload_hash": "",
                "signature": "",
            }, pid)
        ]
        r = module_client.post("/api/sync/push", json={"pid": other_pid, "events": events})
        assert r.status_code == 200
        assert r.json()["applied"] == 0
        evt = (
            module_db.query(models.SyncEvent)
            .filter(models.SyncEvent.instance_id == "inst-retarget")
            .first()
        )
        assert evt is None

    def test_push_rejects_tampered_envelope(self, module_client: TestClient, module_db: Session):
        """Security audit 2026-10-07 (finding 4): flipping op/entity_id/seq on
        a validly-signed event invalidates the signature (envelope-bound)."""
        pid = _state["pid"]
        host = models.Host(id="h-tamper", pid=pid, ip="10.7.7.7", hostname="victim")
        module_db.add(host)
        module_db.commit()

        events = [
            _signed_event({
                "instance_id": "inst-tamper",
                "seq": 1,
                "entity_type": "host",
                "entity_id": "h-innocent",
                "op": "create",
                "payload": {"data": {"ip": "10.0.0.99", "hostname": "original"}},
                "payload_hash": "",
                "signature": "",
            }, pid)
        ]
        tampered = dict(events[0])
        tampered["op"] = "delete"
        tampered["entity_id"] = "h-tamper"
        r = module_client.post("/api/sync/push", json={"pid": pid, "events": [tampered]})
        assert r.status_code == 200
        assert r.json()["applied"] == 0
        victim = module_db.query(models.Host).filter(models.Host.id == "h-tamper").first()
        assert victim is not None
        assert getattr(victim, "deleted_at", None) is None

    def test_push_rejects_fresh_instance_replay(self, module_client: TestClient, module_db: Session):
        """Security audit 2026-10-07 (finding 4): re-issuing a captured signed
        event under a new instance_id (seq reset to 1) must fail — the
        instance_id is inside the signed envelope now."""
        pid = _state["pid"]
        base = {
            "seq": 1,
            "entity_type": "note",
            "entity_id": "n-replay",
            "op": "create",
            "payload": {"content": "captured"},
            "payload_hash": "",
            "signature": "",
        }
        original = _signed_event(dict(base, instance_id="inst-replay-orig"), pid)
        r = module_client.post("/api/sync/push", json={"pid": pid, "events": [original]})
        assert r.status_code == 200
        assert r.json()["applied"] == 1
        replay = _signed_event(dict(base, instance_id="inst-replay-clone"), pid)
        replay["signature"] = original["signature"]  # reuse the captured signature
        r = module_client.post("/api/sync/push", json={"pid": pid, "events": [replay]})
        assert r.status_code == 200
        assert r.json()["applied"] == 0

    def test_push_empty_events(self, module_client: TestClient, module_db: Session):
        pid = _state["pid"]
        r = module_client.post("/api/sync/push", json={"pid": pid, "events": []})
        assert r.status_code == 200
        assert r.json()["applied"] == 0

    def test_push_sequential(self, module_client: TestClient, module_db: Session):
        pid = _state["pid"]
        for seq in range(1, 4):
            events = [
                _signed_event({
                    "instance_id": "inst-seq",
                    "seq": seq,
                    "entity_type": "finding",
                    "entity_id": "f-seq",
                    "op": "update",
                    "payload": {"seq": seq},
                    "payload_hash": "",
                    "signature": "",
                }, pid)
            ]
            r = module_client.post("/api/sync/push", json={"pid": pid, "events": events})
            assert r.status_code == 200
            assert r.json()["applied"] == 1


class TestSyncPull:
    def test_pull_returns_events(self, module_client: TestClient, module_db: Session):
        pid = _state["pid"]
        push_events = [
            _signed_event({
                "instance_id": "inst-pull",
                "seq": 1,
                "entity_type": "finding",
                "entity_id": "f-100",
                "op": "create",
                "payload": {},
                "payload_hash": "",
                "signature": "",
            }, pid),
            _signed_event({
                "instance_id": "inst-pull",
                "seq": 2,
                "entity_type": "finding",
                "entity_id": "f-100",
                "op": "update",
                "payload": {"title": "updated"},
                "payload_hash": "",
                "signature": "",
            }, pid),
        ]
        module_client.post("/api/sync/push", json={"pid": pid, "events": push_events})

        r = module_client.get(f"/api/sync/pull?instance_id=inst-pull&since_seq=0&pid={pid}")
        assert r.status_code == 200
        data = r.json()
        assert len(data["events"]) == 2

        r = module_client.get(f"/api/sync/pull?instance_id=inst-pull&since_seq=1&pid={pid}")
        assert r.status_code == 200
        assert len(r.json()["events"]) == 1


class TestSyncStatus:
    def test_status_returns_data(self, module_client: TestClient, module_db: Session):
        pid = _state["pid"]
        r = module_client.get(f"/api/sync/status?pid={pid}")
        assert r.status_code == 200
        assert "instances" in r.json()
        assert "pending_conflicts" in r.json()


class TestConflictResolution:
    def test_push_creates_conflict(self, module_client: TestClient, module_db: Session):
        pid = _state["pid"]

        state = models.SyncState(
            id=new_id("ss"),
            instance_id="inst-conf",
            entity_type="finding",
            entity_id="f-conf",
            local_version=3,
            remote_version=1,
            last_synced_at=TS,
            status="conflict",
            origin_instance="inst-conf",
        )
        module_db.add(state)
        module_db.commit()

        events = [
            _signed_event({
                "instance_id": "inst-conf",
                "seq": 2,
                "entity_type": "finding",
                "entity_id": "f-conf",
                "op": "update",
                "payload": {"data": {"title": "remote version", "ts": TS}},
                "payload_hash": "",
                "signature": "",
            }, pid)
        ]
        r = module_client.post("/api/sync/push", json={"pid": pid, "events": events})
        assert r.status_code == 200
        assert r.json()["conflicts"] == 1

        conflict = module_db.query(models.ConflictRecord).filter(models.ConflictRecord.entity_id == "f-conf").first()
        assert conflict is not None
        assert conflict.resolution == "pending"

        r = module_client.post(
            f"/api/sync/conflicts/{conflict.id}/resolve",
            json={"pid": pid, "resolution": "remote_wins"},
        )
        assert r.status_code == 200
        assert r.json()["resolution"] == "remote_wins"
        # Audit 2026-08-31, 2.3.2/4.1.4: the winning payload must actually
        # land on the entity, not just be recorded in conflict metadata.
        assert r.json()["applied"] == "created"
        finding = module_db.query(models.Finding).filter(models.Finding.id == "f-conf").first()
        assert finding is not None
        assert finding.title == "remote version"
        assert finding.pid == pid

    def test_manual_resolution(self, module_client: TestClient, module_db: Session):
        pid = _state["pid"]

        conflict = models.ConflictRecord(
            id=new_id("cfl"),
            entity_type="note",
            entity_id="n-manual",
            local_payload={"content": "local"},
            remote_payload={"content": "remote"},
            detected_at=TS,
            pid=pid,
        )
        module_db.add(conflict)
        module_db.commit()

        r = module_client.post(
            f"/api/sync/conflicts/{conflict.id}/resolve",
            json={
                "pid": pid,
                "resolution": "manual",
                "manual_payload": {"title": "merged note", "content": "merged", "ts": TS},
            },
        )
        assert r.status_code == 200
        assert r.json()["resolution"] == "manual"
        assert r.json()["applied"] == "created"
        note = module_db.query(models.Note).filter(models.Note.id == "n-manual").first()
        assert note is not None
        assert note.content == "merged"

    def test_incomplete_payload_fails_loud(
        self, module_client: TestClient, module_db: Session
    ):
        """A winning payload missing required fields must be a 400 with a
        reason — never a silent non-application or a 500 (audit 2.3.2)."""
        pid = _state["pid"]
        conflict = models.ConflictRecord(
            id=new_id("cfl"),
            entity_type="note",
            entity_id="n-incomplete",
            local_payload={},
            remote_payload={"data": {"content": "no title, no ts"}},
            detected_at=TS,
            pid=pid,
        )
        module_db.add(conflict)
        module_db.commit()

        r = module_client.post(
            f"/api/sync/conflicts/{conflict.id}/resolve",
            json={"pid": pid, "resolution": "remote_wins"},
        )
        assert r.status_code == 400
        assert "constraints" in r.json()["detail"]
        module_db.rollback()
        module_db.refresh(conflict)
        assert conflict.resolution == "pending"

    def test_local_wins_keeps_local_data_and_bumps_remote_version(
        self, module_client: TestClient, module_db: Session
    ):
        pid = _state["pid"]

        host = models.Host(id="h-lw", pid=pid, ip="10.9.9.9", hostname="local-truth")
        module_db.add(host)
        state = models.SyncState(
            id=new_id("ss"),
            instance_id="inst-lw",
            entity_type="host",
            entity_id="h-lw",
            local_version=7,
            remote_version=2,
            last_synced_at=TS,
            status="conflict",
            origin_instance="inst-lw",
        )
        conflict = models.ConflictRecord(
            id=new_id("cfl"),
            entity_type="host",
            entity_id="h-lw",
            local_payload={"version": 7},
            remote_payload={"data": {"hostname": "remote-lie"}},
            detected_at=TS,
            pid=pid,
        )
        module_db.add_all([state, conflict])
        module_db.commit()

        r = module_client.post(
            f"/api/sync/conflicts/{conflict.id}/resolve",
            json={"pid": pid, "resolution": "local_wins"},
        )
        assert r.status_code == 200
        assert r.json()["applied"] == "local_unchanged"
        module_db.refresh(host)
        assert host.hostname == "local-truth"  # remote payload NOT applied
        module_db.refresh(state)
        assert state.status == "in_sync"
        assert state.remote_version == 7  # acknowledged, no re-conflict

    def test_remote_wins_updates_existing_entity(
        self, module_client: TestClient, module_db: Session
    ):
        pid = _state["pid"]

        host = models.Host(id="h-rw", pid=pid, ip="10.9.9.8", hostname="stale")
        conflict = models.ConflictRecord(
            id=new_id("cfl"),
            entity_type="host",
            entity_id="h-rw",
            local_payload={"version": 1},
            remote_payload={"data": {"hostname": "fresh-from-remote"}},
            detected_at=TS,
            pid=pid,
        )
        module_db.add_all([host, conflict])
        module_db.commit()

        r = module_client.post(
            f"/api/sync/conflicts/{conflict.id}/resolve",
            json={"pid": pid, "resolution": "remote_wins"},
        )
        assert r.status_code == 200
        assert r.json()["applied"] == "updated"
        module_db.refresh(host)
        assert host.hostname == "fresh-from-remote"

    def test_unsupported_entity_type_rejected(
        self, module_client: TestClient, module_db: Session
    ):
        pid = _state["pid"]
        conflict = models.ConflictRecord(
            id=new_id("cfl"),
            entity_type="mystery_type",
            entity_id="x-1",
            local_payload={},
            remote_payload={"data": {"a": 1}},
            detected_at=TS,
            pid=pid,
        )
        module_db.add(conflict)
        module_db.commit()

        r = module_client.post(
            f"/api/sync/conflicts/{conflict.id}/resolve",
            json={"pid": pid, "resolution": "remote_wins"},
        )
        assert r.status_code == 400
        assert "Unsupported entity_type" in r.json()["detail"]
        module_db.refresh(conflict)
        assert conflict.resolution == "pending"  # not silently "resolved"

    def test_cross_project_conflict_not_resolvable(
        self, module_client: TestClient, module_db: Session
    ):
        pid = _state["pid"]
        conflict = models.ConflictRecord(
            id=new_id("cfl"),
            entity_type="note",
            entity_id="n-other",
            local_payload={},
            remote_payload={"data": {"content": "x"}},
            detected_at=TS,
            pid="prj_some_other_project",
        )
        module_db.add(conflict)
        module_db.commit()

        r = module_client.post(
            f"/api/sync/conflicts/{conflict.id}/resolve",
            json={"pid": pid, "resolution": "remote_wins"},
        )
        assert r.status_code == 404

    def test_already_resolved_conflict_rejected(
        self, module_client: TestClient, module_db: Session
    ):
        pid = _state["pid"]
        conflict = models.ConflictRecord(
            id=new_id("cfl"),
            entity_type="note",
            entity_id="n-done",
            local_payload={},
            remote_payload={"data": {"content": "x"}},
            detected_at=TS,
            pid=pid,
            resolution="manual",
        )
        module_db.add(conflict)
        module_db.commit()

        r = module_client.post(
            f"/api/sync/conflicts/{conflict.id}/resolve",
            json={"pid": pid, "resolution": "remote_wins"},
        )
        assert r.status_code == 400

    def test_invalid_resolution(self, module_client: TestClient, module_db: Session):
        pid = _state["pid"]

        conflict = models.ConflictRecord(
            id=new_id("cfl"),
            entity_type="note",
            entity_id="n-bad",
            local_payload={},
            remote_payload={},
            detected_at=TS,
        )
        module_db.add(conflict)
        module_db.commit()

        r = module_client.post(
            f"/api/sync/conflicts/{conflict.id}/resolve",
            json={"pid": pid, "resolution": "invalid_choice"},
        )
        assert r.status_code == 400

    def test_not_found_conflict(self, module_client: TestClient, module_db: Session):
        pid = _state["pid"]
        r = module_client.post(
            "/api/sync/conflicts/nonexistent/resolve",
            json={"pid": pid, "resolution": "local_wins"},
        )
        assert r.status_code == 404


class TestSyncPolicy:
    def test_get_default_policy(self, module_client: TestClient, module_db: Session):
        pid = _state["pid"]
        r = module_client.get(f"/api/sync/policy?pid={pid}")
        assert r.status_code == 200
        data = r.json()
        assert data["direction"] == "bidirectional"
        assert data["conflict_resolution"] == "manual"

    def test_update_policy(self, module_client: TestClient, module_db: Session):
        pid = _state["pid"]
        r = module_client.put(
            "/api/sync/policy",
            json={
                "pid": pid,
                "sync_entities": ["attack_path", "finding", "task"],
                "direction": "bidirectional",
                "conflict_resolution": "manual",
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["sync_entities"] == ["attack_path", "finding", "task"]

        r = module_client.get(f"/api/sync/policy?pid={pid}")
        assert r.status_code == 200
        assert r.json()["sync_entities"] == ["attack_path", "finding", "task"]

    def test_invalid_direction(self, module_client: TestClient, module_db: Session):
        pid = _state["pid"]
        r = module_client.put(
            "/api/sync/policy",
            json={"pid": pid, "direction": "invalid"},
        )
        assert r.status_code == 400

    def test_invalid_conflict_resolution(self, module_client: TestClient, module_db: Session):
        pid = _state["pid"]
        r = module_client.put(
            "/api/sync/policy",
            json={"pid": pid, "direction": "bidirectional", "conflict_resolution": "auto_merge"},
        )
        assert r.status_code == 400
