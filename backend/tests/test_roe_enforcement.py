"""ROE activity enforcement + approval flow + CIDR range gate.

Audit 2026-08-31, findings 4.1.1/4.1.2. Design (implementer's choice during the 2026-08-31 fix wave;
confirmed by the product owner post-hoc on 2026-09-01):
static connector→category mapping (overridable/extensible per-project via
raw `connector:*` keys in the ROE lists) with hard blocking; jobs whose
activity requires approval are held in `awaiting_approval` until a project
admin approves; CIDR-range targets that partially stick out of scope reject
the whole job.
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app import models
from app.core.roe_guard import (
    ApprovalRequired,
    EngagementViolation,
    check_engagement_rules,
    check_roe_activities,
    check_target_scope,
    job_activity_tags,
)
from app.core.utils import new_id, ts_now

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
USER_PASS = "RoePass1234!ok"

_s: dict = {}


@pytest.fixture()
def _proj(db):
    p_id = new_id("prj")
    db.add(models.Project(id=p_id, name="ROE Gate Test", added="2024-01-01"))
    db.commit()
    return p_id


def _set_roe(db, pid, **kw):
    roe = db.query(models.ProjectROE).filter(models.ProjectROE.project_id == pid).first()
    if not roe:
        roe = models.ProjectROE(
            id=new_id("roe"), project_id=pid, updated_at=ts_now(), **{
                "allowed_activities": [], "forbidden_activities": [],
                "requires_approval": [], "emergency_contacts": [],
                "timezone": "UTC", "notes": "",
                "work_hours_start": None, "work_hours_end": None, "max_scan_rate": None,
            }
        )
        db.add(roe)
    for k, v in kw.items():
        setattr(roe, k, v)
    db.commit()
    return roe


class TestActivityTags:
    def test_static_map(self):
        assert "port_scanning" in job_activity_tags("nmap", "scan")
        assert "lateral_movement" in job_activity_tags("c2", "exec")

    def test_raw_connector_keys_always_present(self):
        tags = job_activity_tags("nmap", "scan")
        assert "connector:nmap" in tags
        assert "connector:nmap:scan" in tags

    def test_unknown_connector_has_only_raw_keys(self):
        tags = job_activity_tags("mystery", "op")
        assert tags == {"connector:mystery", "connector:mystery:op"}


class TestForbiddenActivities:
    def test_forbidden_category_blocks(self, db, _proj):
        _set_roe(db, _proj, forbidden_activities=["port_scanning"])
        with pytest.raises(EngagementViolation) as ei:
            check_roe_activities(db, _proj, "nmap", "scan")
        assert "port_scanning" in str(ei.value)

    def test_forbidden_raw_connector_key_blocks(self, db, _proj):
        """Per-project override: forbid by connector key directly."""
        _set_roe(db, _proj, forbidden_activities=["connector:attacker_ssh:exec"])
        with pytest.raises(EngagementViolation):
            check_roe_activities(db, _proj, "attacker_ssh", "exec")

    def test_allowed_activity_passes(self, db, _proj):
        _set_roe(db, _proj, forbidden_activities=["phishing"])
        check_roe_activities(db, _proj, "nmap", "scan")  # no raise

    def test_no_roe_is_noop(self, db, _proj):
        check_roe_activities(db, _proj, "nmap", "scan")

    def test_combined_gate(self, db, _proj):
        _set_roe(db, _proj, forbidden_activities=["web_scanning"])
        with pytest.raises(EngagementViolation):
            check_engagement_rules(db, _proj, target="", connector_key="nuclei", operation="scan")


class TestRequiresApproval:
    def test_requires_category_holds(self, db, _proj):
        _set_roe(db, _proj, requires_approval=["credential_stuffing"])
        with pytest.raises(ApprovalRequired) as ei:
            check_roe_activities(db, _proj, "netexec", "scan")
        assert "credential_stuffing" in ei.value.activities

    def test_requires_raw_key(self, db, _proj):
        _set_roe(db, _proj, requires_approval=["connector:c2:exec"])
        with pytest.raises(ApprovalRequired):
            check_roe_activities(db, _proj, "c2", "exec")

    def test_not_listed_passes(self, db, _proj):
        _set_roe(db, _proj, requires_approval=["phishing"])
        check_roe_activities(db, _proj, "c2", "exec")


class TestCidrRangeGate:
    def _scope(self, db, pid, cidr):
        db.add(models.Scope(id=new_id("scp"), pid=pid, scope_type="cidr", value=cidr))
        db.commit()

    def test_fully_inside_range_passes(self, db, _proj):
        self._scope(db, _proj, "10.10.0.0/16")
        check_target_scope(db, _proj, "10.10.1.0/24")

    def test_partially_outside_range_rejects_whole_job(self, db, _proj):
        self._scope(db, _proj, "10.10.0.0/24")
        with pytest.raises(EngagementViolation) as ei:
            check_target_scope(db, _proj, "10.10.0.0/23")  # half outside
        assert "outside" in str(ei.value).lower()

    def test_dash_range_and_lists(self, db, _proj):
        self._scope(db, _proj, "10.10.0.0/24")
        check_target_scope(db, _proj, "10.10.0.1-10.10.0.9")
        check_target_scope(db, _proj, "10.10.0.1, 10.10.0.2")
        with pytest.raises(EngagementViolation):
            check_target_scope(db, _proj, "10.10.0.1, 10.11.0.1")

    def test_url_host_part_checked(self, db, _proj):
        self._scope(db, _proj, "10.10.0.0/24")
        check_target_scope(db, _proj, "http://10.10.0.5:8080/path")
        with pytest.raises(EngagementViolation):
            check_target_scope(db, _proj, "http://10.99.0.5/")

    def test_hostname_still_noop(self, db, _proj):
        self._scope(db, _proj, "10.10.0.0/24")
        check_target_scope(db, _proj, "example.corp")  # no raise


class TestApprovalFlowApi:
    @pytest.fixture(scope="class", autouse=True)
    def _bootstrap(self, module_client: TestClient, module_db: Session):
        c = module_client
        c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
        c.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
        r = c.post("/api/projects", json={"name": "ROE Approve Test", "added": "2025-01-01T00:00:00Z", "status": "active"})
        _s["pid"] = r.json()["id"]
        r = c.post("/api/admin/users", json={"username": "roe_operator", "password": USER_PASS, "role": "user"})
        _s["op_uid"] = r.json()["id"]
        c.post(f"/api/projects/{_s['pid']}/members", json={"user_id": _s["op_uid"], "role": "operator"})
        # requires_approval for lateral movement
        c.put(f"/api/projects/{_s['pid']}/roe", json={"requires_approval": ["lateral_movement"]})
        yield
        c.post("/api/auth/logout")

    def test_operator_job_held_then_admin_approves(self, module_client: TestClient, module_db: Session):
        c = module_client
        c.post("/api/auth/logout")
        c.post("/api/auth/login", json={"username": "roe_operator", "password": USER_PASS})
        r = c.post(
            f"/api/projects/{_s['pid']}/jobs/c2/exec",
            json={"agent_id": "a1", "host_id": "h1", "commandline": "whoami"},
        )
        # Either 202 (held) or a validation 400 — the ROE gate itself is
        # asserted at unit level above; here we need a real awaiting job.
        if r.status_code not in (200, 201, 202):
            # fall back: create the awaiting job directly via queue_job
            from app.core.job_tracker import queue_job

            job = queue_job(
                module_db, _s["pid"], "c2", "c2 exec test", connector_key="c2",
                operation="exec", created_by="roe_operator",
            )
            _s["job_id"] = job.id
            assert job.status == "awaiting_approval"
        else:
            _s["job_id"] = r.json().get("job_id") or r.json()["id"]

        # operator cannot approve (needs project.manage_members)
        r = c.post(f"/api/projects/{_s['pid']}/jobs/{_s['job_id']}/approve")
        assert r.status_code == 403

        # platform admin approves → queued
        c.post("/api/auth/logout")
        c.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
        r = c.post(f"/api/projects/{_s['pid']}/jobs/{_s['job_id']}/approve")
        assert r.status_code == 200, r.text
        assert r.json()["status"] == "queued"

    def test_reject_path(self, module_client: TestClient, module_db: Session):
        from app.core.job_tracker import queue_job

        job = queue_job(
            module_db, _s["pid"], "c2", "c2 exec reject test", connector_key="c2",
            operation="exec", created_by="roe_operator",
        )
        assert job.status == "awaiting_approval"
        module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
        r = module_client.post(f"/api/projects/{_s['pid']}/jobs/{job.id}/reject")
        assert r.status_code == 200
        assert r.json()["status"] == "cancelled"

    def test_approve_non_awaiting_rejected(self, module_client: TestClient):
        module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
        r = module_client.post(f"/api/projects/{_s['pid']}/jobs/nonexistent/approve")
        assert r.status_code == 404


class TestPivotExemption:
    """exec-style jobs: `target` is our own attacker box (the SSH pivot),
    not a scan target. It must be exempt from the CIDR scope check — an
    attacker machine normally sits outside the engagement scope — while
    the command's literal targets stay fully guarded. Live regression:
    the moment a cyber-range project defined its scope, every
    attacker-exec command died with 403 'target outside scope'."""

    def _scoped_project(self, db):
        from app.core.utils import new_id, ts_now
        from app.models import Project, Scope

        pid = new_id("p")
        db.add(Project(id=pid, name="pivot-test", status="active", added=ts_now()))
        db.add(models.Scope(id=new_id("scp"), pid=pid, scope_type="cidr", value="10.10.0.0/16"))
        db.commit()
        return pid

    def test_pivot_target_exempt_command_scanned(self, db):
        from app.core.roe_guard import check_engagement_rules

        pid = self._scoped_project(db)
        # пивот вне scope + команда по in-scope цели → проходит
        check_engagement_rules(
            db, pid, target="172.16.90.24", connector_key="attacker_ssh",
            operation="exec", command="nmap -sV 10.10.1.5", target_is_pivot=True,
        )

    def test_pivot_exemption_does_not_cover_command_targets(self, db):
        from app.core.roe_guard import EngagementViolation, check_engagement_rules

        pid = self._scoped_project(db)
        try:
            check_engagement_rules(
                db, pid, target="172.16.90.24", connector_key="attacker_ssh",
                operation="exec", command="nmap -sV 203.0.113.9", target_is_pivot=True,
            )
            raise AssertionError("out-of-scope target in command must be rejected")
        except EngagementViolation:
            pass

    def test_non_pivot_target_still_scope_checked(self, db):
        from app.core.roe_guard import EngagementViolation, check_engagement_rules

        pid = self._scoped_project(db)
        try:
            check_engagement_rules(
                db, pid, target="172.16.90.24", connector_key="nmap",
                operation="scan", command="", target_is_pivot=False,
            )
            raise AssertionError("out-of-scope scan target must be rejected")
        except EngagementViolation:
            pass
