"""Startup recovery for interrupted PlaybookRuns (audit 2026-08-31, 2.3.4).

Runs live as asyncio tasks in the API process — a restart orphans their DB
rows in running/queued forever. Recovery marks them failed with an explicit
reason, mirroring worker_pool.startup_recovery for Jobs.
"""
import pytest

from app import models
from app.core.utils import new_id, ts_now


@pytest.fixture()
def pid(db):
    p_id = new_id("prj")
    db.add(models.Project(id=p_id, name="Recovery Test", added="2024-01-01"))
    db.commit()
    return p_id


def _make_run(db, pid, status):
    run = models.PlaybookRun(
        id=new_id("run"),
        pid=pid,
        playbook_id="pb_test",
        title="recovery test run",
        status=status,
        created_by="tester",
        created_at=ts_now(),
        jobs_json=[],
        request_json={},
    )
    db.add(run)
    db.commit()
    return run


class TestPlaybookRunStartupRecovery:
    def test_orphans_failed_with_reason(self, db, pid):
        from app.main import _recover_interrupted_playbook_runs

        running = _make_run(db, pid, "running")
        queued = _make_run(db, pid, "queued")
        done = _make_run(db, pid, "done")

        recovered = _recover_interrupted_playbook_runs(db)

        # Other suites may leave orphaned rows in the shared test DB —
        # assert on THIS project's runs, not the global count.
        assert recovered >= 2
        for row in (running, queued):
            db.refresh(row)
            assert row.status == "failed"
            assert "[interrupted: backend restarted" in (row.error_output or "")
            assert row.finished_at  # terminal timestamp recorded
        db.refresh(done)
        assert done.status == "done"  # untouched

    def test_no_orphans_is_noop(self, db, pid):
        from app.main import _recover_interrupted_playbook_runs

        _make_run(db, pid, "done")
        _make_run(db, pid, "failed")
        before = (
            db.query(models.PlaybookRun)
            .filter(models.PlaybookRun.pid == pid)
            .count()
        )
        _recover_interrupted_playbook_runs(db)
        after = (
            db.query(models.PlaybookRun)
            .filter(models.PlaybookRun.pid == pid, models.PlaybookRun.status == "failed")
            .count()
        )
        assert after == before - 1  # only the pre-existing 'failed' one

    def test_idempotent(self, db, pid):
        from app.main import _recover_interrupted_playbook_runs

        _make_run(db, pid, "running")
        _recover_interrupted_playbook_runs(db)
        again = (
            db.query(models.PlaybookRun)
            .filter(models.PlaybookRun.pid == pid, models.PlaybookRun.status == "running")
            .count()
        )
        assert again == 0  # nothing left in running for a second pass


# ════════ awaiting_approval runs survive recovery (review follow-up) ════════


class TestAwaitingApprovalRunSurvivesRecovery:
    """Review follow-up (4.1.1/4.1.2 x 2.3.4/4.1.6): a run with a step-job
    held by the ROE approval gate is a deliberate pause, not a hung process
    — startup recovery must not fail it."""

    def _make_run_with_job(self, db, pid, job_status):
        from app.core.job_tracker import queue_job

        roe = models.ProjectROE(
            id=new_id("roe"), project_id=pid, updated_at=ts_now(),
            allowed_activities=[], forbidden_activities=[],
            requires_approval=["lateral_movement"], emergency_contacts=[],
            timezone="UTC", notes="", max_scan_rate=None,
        )
        db.add(roe)
        job = queue_job(
            db, pid, "c2", "awaiting step", connector_key="c2", operation="exec",
            created_by="tester",
        )
        assert job.status == job_status
        run = models.PlaybookRun(
            id=new_id("run"), pid=pid, playbook_id="pb", title="awaiting run",
            status="running", created_by="tester", created_at=ts_now(),
            jobs_json=[{"id": job.id, "status": job_status, "step_idx": 0, "attempt": 1}],
            request_json={},
        )
        db.add(run)
        db.commit()
        return run, job

    def test_recovery_skips_awaiting_approval_run(self, db, pid):
        from app.main import _recover_interrupted_playbook_runs

        run, job = self._make_run_with_job(db, pid, "awaiting_approval")

        recovered = _recover_interrupted_playbook_runs(db)

        assert recovered == 0
        db.refresh(run)
        assert run.status == "running"  # untouched — waiting for a human
        db.refresh(job)
        assert job.status == "awaiting_approval"

    def test_plain_orphan_still_failed(self, db, pid):
        from app.main import _recover_interrupted_playbook_runs

        _make_run(db, pid, "running")  # no jobs at all
        assert _recover_interrupted_playbook_runs(db) == 1

    async def test_full_cycle_restart_approve_execute_finalize(self, db, pid):
        """Run with an awaiting step → restart (recovery pass) → approve →
        job executes → run reaches a terminal state matching the job."""
        from app.core.job_tracker import finish_job
        from app.main import _recover_interrupted_playbook_runs
        from app.routers.playbooks._engine import _resume_run_after_approval

        run, job = self._make_run_with_job(db, pid, "awaiting_approval")

        # backend "restart": recovery must leave the run alone
        assert _recover_interrupted_playbook_runs(db) == 0
        db.refresh(run)
        assert run.status == "running"

        # admin approves → approve_job schedules the resume coroutine; the
        # engine task is dead after the restart, so emulate what it does:
        job.status = "queued"  # approve endpoint's transition
        db.commit()
        # ... the worker then executes it:
        finish_job(db, job, status="done", output="ok")
        await _resume_run_after_approval(run.id, job.id)

        db.refresh(run)
        assert run.status == "done"
        assert run.finished_at
        assert (run.result_json or {}).get("resumed_after_approval") is True

    async def test_full_cycle_rejected_job_cancels_run(self, db, pid):
        from app.core.job_tracker import finish_job
        from app.main import _recover_interrupted_playbook_runs
        from app.routers.playbooks._engine import _resume_run_after_approval

        run, job = self._make_run_with_job(db, pid, "awaiting_approval")
        assert _recover_interrupted_playbook_runs(db) == 0

        # admin rejects: approve endpoint's reject transition
        job.status = "cancelled"
        job.error_output = "Rejected under ROE"
        db.commit()
        await _resume_run_after_approval(run.id, job.id)

        db.refresh(run)
        assert run.status == "cancelled"
        assert run.finished_at

    async def test_live_engine_result_not_overwritten(self, db, pid):
        """If a live engine already finalized the run (no restart), the
        resume coroutine must exit without touching it."""
        from app.core.job_tracker import finish_job
        from app.routers.playbooks._engine import _resume_run_after_approval

        run, job = self._make_run_with_job(db, pid, "awaiting_approval")
        finish_job(db, job, status="done")
        # engine already terminalized:
        run.status = "done"
        run.result_json = {"completed_jobs": [job.id], "engine_live": True}
        db.commit()

        await _resume_run_after_approval(run.id, job.id)
        db.refresh(run)
        assert run.status == "done"
        assert (run.result_json or {}).get("engine_live") is True  # not overwritten
