"""Deconfliction — soft host claims + engagement map."""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.core.utils import new_id, ts_now
from app.models import Host, Job
from app.models.host_claim import HostClaim

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    yield


def _make_project_with_host(client, db, ip="198.51.100.60"):
    r = client.post(
        "/api/projects", json={"name": f"Dc{new_id('d')[:6]}", "added": "2025-01-01T00:00:00Z"}
    )
    assert r.status_code == 201
    pid = r.json()["id"]
    host = Host(id=new_id("hst"), pid=pid, ip=ip, status="up")
    db.add(host)
    db.commit()
    return pid, host.id, ip


class TestClaimLifecycle:
    def test_claim_conflict_release(self, module_client, module_db):
        pid, hid, ip = _make_project_with_host(module_client, module_db)
        _state.update(pid=pid, hid=hid, ip=ip)

        r = module_client.post(f"/api/projects/{pid}/hosts/{hid}/claim", json={"note": "pth chain"})
        assert r.status_code == 200
        assert r.json()["status"] == "claimed"

        # second operator: create + login
        from app.core.security import hash_password
        from app.models import User

        other = User(
            id=new_id("u"),
            username="operator2",
            display_name="operator2",
            password_hash=hash_password("OpPass1234!"),
            role="operator",
            created_at=ts_now(),
            active=True,
        )
        module_db.add(other)
        from app.models import ProjectMember

        module_db.add(ProjectMember(id=new_id("mem"), project_id=pid, user_id=other.id, role="operator", created_at=ts_now()))
        module_db.commit()
        from fastapi.testclient import TestClient as TC

        from app.main import app as main_app

        c2 = TC(main_app, raise_server_exceptions=False)
        r = c2.post("/api/auth/login", json={"username": "operator2", "password": "OpPass1234!"})
        assert r.status_code == 200

        r = c2.post(f"/api/projects/{pid}/hosts/{hid}/claim", json={})
        assert r.status_code == 409, "another operator's active claim must conflict"
        assert "engaged" in r.text

        # release by holder (admin session — its cookies untouched by c2's login)
        r = module_client.delete(f"/api/projects/{pid}/hosts/{hid}/claim")
        assert r.status_code == 204, r.text

        r = c2.post(f"/api/projects/{pid}/hosts/{hid}/claim", json={})
        assert r.status_code == 200

    def test_reclaim_extends(self, module_client, module_db):
        pid, hid, _ = _make_project_with_host(module_client, module_db)
        r1 = module_client.post(f"/api/projects/{pid}/hosts/{hid}/claim", json={})
        r2 = module_client.post(f"/api/projects/{pid}/hosts/{hid}/claim", json={"note": "again"})
        assert r2.status_code == 200
        assert r2.json()["status"] == "extended"
        assert r2.json()["expires_at"] >= r1.json()["expires_at"]
        module_client.delete(f"/api/projects/{pid}/hosts/{hid}/claim")

    def test_expired_claim_conflicts_no_more(self, module_client, module_db):
        pid, hid, _ = _make_project_with_host(module_client, module_db)
        r = module_client.post(f"/api/projects/{pid}/hosts/{hid}/claim", json={})
        assert r.status_code == 200
        # force-expire it directly
        past = (datetime.now(UTC) - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        claim = module_db.query(HostClaim).filter(HostClaim.host_id == hid, HostClaim.active.is_(True)).first()
        claim.expires_at = past
        module_db.commit()

        r = module_client.post(f"/api/projects/{pid}/hosts/{hid}/claim", json={})
        assert r.status_code == 200, "expired claim must not conflict"


class TestEngagementMap:
    def test_merges_claims_and_running_jobs(self, module_client, module_db):
        pid, hid, ip = _make_project_with_host(module_client, module_db)
        module_client.post(f"/api/projects/{pid}/hosts/{hid}/claim", json={"note": "smb relay"})

        module_db.add(
            Job(
                id=new_id("job"),
                pid=pid,
                type="nmap",
                title="Nmap",
                status="running",
                target=ip,
                created_by="admin", created_at=ts_now(),
            )
        )
        module_db.commit()

        r = module_client.get(f"/api/projects/{pid}/deconfliction")
        assert r.status_code == 200
        engagement = r.json()["engagement"]
        assert hid in engagement
        ops = engagement[hid]["operators"]
        admin_entry = next(o for o in ops if o["username"] == "admin")
        assert set(admin_entry["sources"]) == {"claim", "job"}
        assert admin_entry["is_me"] is True
        assert admin_entry["note"] == "smb relay"

        module_client.delete(f"/api/projects/{pid}/hosts/{hid}/claim")

    def test_subnet_job_not_attributed(self, module_client, module_db):
        pid, hid, ip = _make_project_with_host(module_client, module_db)
        module_db.add(
            Job(
                id=new_id("job"), pid=pid, type="nmap", title="Nmap", status="running",
                target="198.51.100.0/24", created_by="admin", created_at=ts_now(),
            )
        )
        module_db.commit()
        r = module_client.get(f"/api/projects/{pid}/deconfliction")
        # single host inside the subnet range string — ambiguous, must not attribute
        engagement = r.json()["engagement"]
        entry = engagement.get(hid)
        if entry:
            assert all("job" not in o["sources"] for o in entry["operators"])


class TestReleaseAuthority:
    """Release is the operator's top-priority clear.

    Engagement is set by a manual claim and automatically by workstation
    shell activity; jobs add their own signal. It is cleared by the button
    first (outranking every signal, including a still-running job) and by the
    idle timeout second.
    """

    def _running_job(self, db, pid, ip, created_at=None):
        db.add(
            Job(
                id=new_id("job"), pid=pid, type="nmap", title="Nmap", status="running",
                target=ip, created_by="admin", created_at=created_at or ts_now(),
            )
        )
        db.commit()

    def _engagement(self, client, pid):
        r = client.get(f"/api/projects/{pid}/deconfliction")
        assert r.status_code == 200
        return r.json()["engagement"]

    def test_release_clears_a_plain_claim(self, module_client, module_db):
        pid, hid, _ip = _make_project_with_host(module_client, module_db, ip="198.51.100.71")
        module_client.post(f"/api/projects/{pid}/hosts/{hid}/claim", json={"note": ""})
        assert hid in self._engagement(module_client, pid)

        assert module_client.delete(f"/api/projects/{pid}/hosts/{hid}/claim").status_code == 204
        assert hid not in self._engagement(module_client, pid)

    def test_release_outranks_a_running_job(self, module_client, module_db):
        pid, hid, ip = _make_project_with_host(module_client, module_db, ip="198.51.100.72")
        self._running_job(module_db, pid, ip)
        module_client.post(f"/api/projects/{pid}/hosts/{hid}/claim", json={"note": ""})
        assert hid in self._engagement(module_client, pid)

        assert module_client.delete(f"/api/projects/{pid}/hosts/{hid}/claim").status_code == 204
        # The job is still running, but the operator said they are done.
        assert hid not in self._engagement(module_client, pid)

    def test_release_succeeds_with_no_claim_to_drop(self, module_client, module_db):
        """A job-only engagement must still be dismissable (used to 404)."""
        pid, hid, ip = _make_project_with_host(module_client, module_db, ip="198.51.100.73")
        self._running_job(module_db, pid, ip)
        assert hid in self._engagement(module_client, pid)

        assert module_client.delete(f"/api/projects/{pid}/hosts/{hid}/claim").status_code == 204
        assert hid not in self._engagement(module_client, pid)

    def test_releasing_twice_is_not_an_error(self, module_client, module_db):
        pid, hid, _ip = _make_project_with_host(module_client, module_db, ip="198.51.100.74")
        module_client.post(f"/api/projects/{pid}/hosts/{hid}/claim", json={"note": ""})
        assert module_client.delete(f"/api/projects/{pid}/hosts/{hid}/claim").status_code == 204
        assert module_client.delete(f"/api/projects/{pid}/hosts/{hid}/claim").status_code == 204

    def test_activity_after_a_release_re_engages_the_host(self, module_client, module_db):
        pid, hid, ip = _make_project_with_host(module_client, module_db, ip="198.51.100.75")
        self._running_job(module_db, pid, ip)
        assert module_client.delete(f"/api/projects/{pid}/hosts/{hid}/claim").status_code == 204
        assert hid not in self._engagement(module_client, pid)

        # Going back to work on the host brings the engagement back.
        module_client.post(f"/api/projects/{pid}/hosts/{hid}/claim", json={"note": "again"})
        entry = self._engagement(module_client, pid)[hid]
        op = next(o for o in entry["operators"] if o["username"] == "admin")
        assert "claim" in op["sources"]

    def test_release_is_scoped_to_its_host(self, module_client, module_db):
        pid, hid, ip = _make_project_with_host(module_client, module_db, ip="198.51.100.76")
        other = Host(id=new_id("hst"), pid=pid, ip="198.51.100.77", status="up")
        module_db.add(other)
        module_db.commit()
        self._running_job(module_db, pid, ip)
        self._running_job(module_db, pid, "198.51.100.77")

        assert module_client.delete(f"/api/projects/{pid}/hosts/{hid}/claim").status_code == 204
        engagement = self._engagement(module_client, pid)
        assert hid not in engagement
        assert other.id in engagement, "releasing one host must not clear another"


class TestIdleTimeout:
    def test_claim_ttl_is_the_shared_idle_window(self):
        from app.routers.deconfliction import (
            CLAIM_TTL_MINUTES,
            ENGAGEMENT_IDLE_MINUTES,
            WS_ACTIVITY_MINUTES,
        )

        assert ENGAGEMENT_IDLE_MINUTES == 10
        assert CLAIM_TTL_MINUTES == ENGAGEMENT_IDLE_MINUTES
        assert WS_ACTIVITY_MINUTES == ENGAGEMENT_IDLE_MINUTES

    def test_claim_is_dropped_once_it_goes_idle(self, module_client, module_db):
        pid, hid, _ip = _make_project_with_host(module_client, module_db, ip="198.51.100.78")
        module_client.post(f"/api/projects/{pid}/hosts/{hid}/claim", json={"note": ""})
        claim = (
            module_db.query(HostClaim)
            .filter(HostClaim.host_id == hid, HostClaim.active.is_(True))
            .first()
        )
        stale = (datetime.now(UTC).replace(tzinfo=None) - timedelta(minutes=1)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        claim.expires_at = stale
        module_db.commit()

        r = module_client.get(f"/api/projects/{pid}/deconfliction")
        assert hid not in r.json()["engagement"]
        module_db.refresh(claim)
        assert claim.active is False
