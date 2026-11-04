"""Tests for app.core.job_tracker — job lifecycle helpers."""

import pytest
from sqlalchemy.orm import Session

from app import models
from app.core.job_tracker import _job_dict, finish_job, mark_job_running, queue_job, start_job
from app.core.roe_guard import EngagementViolation
from app.core.utils import new_id, ts_now


@pytest.fixture()
def pid(db: Session) -> str:
    p_id = new_id("prj")
    db.add(models.Project(id=p_id, name="Test Project", added="2024-01-01"))
    db.commit()
    return p_id


class TestJobDict:
    def test_serializes_job(self, db: Session, pid: str):
        job = queue_job(db, pid, "nmap", "test", connector_key="nmap", operation="scan")
        d = _job_dict(job)
        assert d["id"] == job.id
        assert d["pid"] == pid
        assert d["status"] == "queued"
        assert d["type"] == "nmap"
        assert d["request_json"] == {}
        assert d["result_json"] == {}


class TestStartJob:
    def test_creates_running_job(self, db: Session, pid: str):
        job = start_job(
            db, pid, "nmap", "test scan", target="10.0.0.1", command="nmap -sV 10.0.0.1"
        )
        assert job.status == "running"
        assert job.target == "10.0.0.1"
        assert job.started_at != ""
        assert job.created_at != ""

    def test_with_related_entity(self, db: Session, pid: str):
        job = start_job(db, pid, "nmap", "test", related_entity=("host", "h1"))
        assert job.related_entity_type == "host"
        assert job.related_entity_id == "h1"

    def test_with_request_json(self, db: Session, pid: str):
        job = start_job(db, pid, "nmap", "test", request_json={"key": "value"})
        assert job.request_json == {"key": "value"}


class TestQueueJob:
    def test_creates_queued_job(self, db: Session, pid: str):
        job = queue_job(db, pid, "nmap", "test", target="10.0.0.1")
        assert job.status == "queued"
        assert job.started_at == ""

    def test_with_scope(self, db: Session, pid: str):
        job = queue_job(db, pid, "nmap", "test", scope=("global", "g1"))
        assert job.scope_type == "global"
        assert job.scope_id == "g1"

    def test_with_retry_opts(self, db: Session, pid: str):
        job = queue_job(
            db,
            pid,
            "nmap",
            "test",
            retry_opts={"retry_of_job_id": "j1", "retry_count": 1, "max_retries": 3, "priority": 5},
        )
        assert job.retry_of_job_id == "j1"
        assert job.retry_count == 1
        assert job.max_retries == 3


class TestMarkJobRunning:
    def test_updates_status(self, db: Session, pid: str):
        job = queue_job(db, pid, "nmap", "test")
        updated = mark_job_running(db, job)
        assert updated.status == "running"
        assert updated.started_at != ""


class TestFinishJob:
    def test_marks_done(self, db: Session, pid: str):
        job = start_job(db, pid, "nmap", "test")
        updated = finish_job(db, job, status="done", output="scan complete")
        assert updated.status == "done"
        assert updated.output == "scan complete"
        assert updated.finished_at != ""

    def test_marks_failed(self, db: Session, pid: str):
        job = start_job(db, pid, "nmap", "test")
        updated = finish_job(db, job, status="failed", error_output="timeout")
        assert updated.status == "failed"
        assert updated.error_output == "timeout"

    def test_cancelled_not_overwritten(self, db: Session, pid: str):
        job = start_job(db, pid, "nmap", "test")
        job.status = "cancelled"
        db.commit()
        updated = finish_job(db, job, status="done", output="late result")
        assert updated.status == "cancelled"

    def test_with_result_json(self, db: Session, pid: str):
        job = start_job(db, pid, "nmap", "test")
        updated = finish_job(db, job, status="done", result={"hosts": 5})
        assert updated.result_json == {"hosts": 5}

    def test_default_result_json(self, db: Session, pid: str):
        job = start_job(db, pid, "nmap", "test")
        updated = finish_job(db, job, status="done")
        assert updated.result_json == {}


class TestEngagementGuard:
    """job_tracker.start_job/queue_job reject targets outside a project's
    CIDR scope or ROE work-hours window (docs/modules/COMPREHENSIVE_AUDIT_2026-08-31.md
    findings 4.1.1/4.1.2)."""

    def _in_scope_cidr(self, db: Session, pid: str, cidr: str = "10.0.0.0/24") -> None:
        db.add(
            models.Scope(
                id=new_id("scp"),
                pid=pid,
                value=cidr,
                scope_type="cidr",
                in_scope=True,
            )
        )
        db.commit()

    def test_start_job_no_scope_defined_is_noop(self, db: Session, pid: str):
        # No Scope rows for this project → scope check is a no-op, matching
        # filter_parsed_hosts_in_scope's existing behaviour.
        job = start_job(db, pid, "nmap", "test", target="8.8.8.8")
        assert job.status == "running"

    def test_start_job_target_in_scope_allowed(self, db: Session, pid: str):
        self._in_scope_cidr(db, pid)
        job = start_job(db, pid, "nmap", "test", target="10.0.0.5")
        assert job.status == "running"

    def test_start_job_target_out_of_scope_raises_and_marks_failed(self, db: Session, pid: str):
        self._in_scope_cidr(db, pid)
        with pytest.raises(EngagementViolation):
            start_job(db, pid, "c2_exec", "test", target="8.8.8.8")
        job = db.query(models.Job).filter(models.Job.pid == pid).first()
        assert job.status == "failed"
        assert "outside the project's defined scope" in job.error_output

    def test_start_job_non_ip_target_is_not_checked(self, db: Session, pid: str):
        self._in_scope_cidr(db, pid)
        # httpx/ffuf targets are URLs, not bare IPs — scope check is a no-op
        # for anything that isn't a literal IP address (documented limitation).
        job = start_job(db, pid, "httpx", "test", target="https://example.com/")
        assert job.status == "running"

    def test_queue_job_out_of_scope_finishes_failed_without_raising(self, db: Session, pid: str):
        self._in_scope_cidr(db, pid)
        # Unlike start_job, queue_job must not raise — nothing runs
        # synchronously right after it; the job is simply created already
        # terminal so run_queued_job's status guard keeps it from executing.
        job = queue_job(
            db, pid, "c2", "test", target="8.8.8.8", connector_key="c2", operation="exec"
        )
        assert job.status == "failed"
        assert "outside the project's defined scope" in job.error_output

    def test_queue_job_in_scope_stays_queued(self, db: Session, pid: str):
        self._in_scope_cidr(db, pid)
        job = queue_job(
            db, pid, "c2", "test", target="10.0.0.5", connector_key="c2", operation="exec"
        )
        assert job.status == "queued"

    def test_start_job_outside_work_hours_blocked(self, db: Session, pid: str):
        db.add(
            models.ProjectROE(
                id=new_id("roe"),
                project_id=pid,
                # A one-minute window in the past guarantees "now" falls
                # outside it regardless of when the test suite runs.
                work_hours_start="00:00",
                work_hours_end="00:01",
                timezone="UTC",
                updated_at=ts_now(),
            )
        )
        db.commit()
        with pytest.raises(EngagementViolation):
            start_job(db, pid, "nmap", "test", target="10.0.0.5")

    def test_start_job_command_target_out_of_scope_raises_and_marks_failed(
        self, db: Session, pid: str
    ):
        # attacker-exec-style jobs: `target` is the in-scope SSH pivot host,
        # the real operation target only exists as a free-form argument
        # inside `command` — a pivot inside scope let an operator hit any
        # out-of-scope target the command named (security retest, 2026-09-03).
        self._in_scope_cidr(db, pid)
        with pytest.raises(EngagementViolation):
            start_job(
                db,
                pid,
                "exec",
                "test",
                target="10.0.0.5",
                command="nmap -sT 203.0.113.5",
                connector_key="attacker_ssh",
                operation="exec",
            )
        job = db.query(models.Job).filter(models.Job.pid == pid).first()
        assert job.status == "failed"
        assert "outside the project's defined scope" in job.error_output

    def test_start_job_command_target_in_scope_allowed(self, db: Session, pid: str):
        self._in_scope_cidr(db, pid)
        job = start_job(
            db,
            pid,
            "exec",
            "test",
            target="10.0.0.5",
            command="whoami && id 10.0.0.9",
            connector_key="attacker_ssh",
            operation="exec",
        )
        assert job.status == "running"

    def test_queue_job_command_target_out_of_scope_finishes_failed_without_raising(
        self, db: Session, pid: str
    ):
        self._in_scope_cidr(db, pid)
        job = queue_job(
            db,
            pid,
            "exec",
            "test",
            target="10.0.0.5",
            command="nmap -sT 203.0.113.5",
            connector_key="attacker_ssh",
            operation="exec",
        )
        assert job.status == "failed"
        assert "outside the project's defined scope" in job.error_output

    def test_start_job_no_roe_work_hours_is_noop(self, db: Session, pid: str):
        # ProjectROE row exists but doesn't define work hours → no-op.
        db.add(
            models.ProjectROE(
                id=new_id("roe"),
                project_id=pid,
                timezone="UTC",
                updated_at=ts_now(),
            )
        )
        db.commit()
        job = start_job(db, pid, "nmap", "test", target="10.0.0.5")
        assert job.status == "running"
