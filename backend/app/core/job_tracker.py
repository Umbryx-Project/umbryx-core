"""
Lightweight job tracking helpers.
Each job represents one tool invocation (nmap, nuclei, cme, exec, etc.)
with a status lifecycle: queued → running → done | failed | cancelled.
"""

import logging
from contextlib import contextmanager

from fastapi import HTTPException
from sqlalchemy.orm import Session

from .. import models
from ..core.events import bcast, log_event
from ..core.roe_guard import ApprovalRequired, EngagementViolation, check_engagement_rules
from ..core.utils import new_id, ts_now

logger = logging.getLogger(__name__)


def _now() -> str:
    return ts_now()


def _job_dict(job: models.Job) -> dict:
    return {
        "id": job.id,
        "pid": job.pid,
        "type": job.type,
        "connector_key": job.connector_key,
        "operation": job.operation,
        "status": job.status,
        "title": job.title,
        "target": job.target,
        "command": job.command,
        "output": job.output,
        "error_output": job.error_output,
        "created_by": job.created_by,
        "scope_type": job.scope_type,
        "scope_id": job.scope_id,
        "related_entity_type": job.related_entity_type,
        "related_entity_id": job.related_entity_id,
        "retry_of_job_id": job.retry_of_job_id,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "request_json": job.request_json or {},
        "result_json": job.result_json or {},
    }


def start_job(
    db: Session,
    pid: str,
    job_type: str,
    title: str,
    *,
    target: str = "",
    command: str = "",
    created_by: str = "",
    connector_key: str = "",
    operation: str = "",
    scope_type: str = "project",
    scope_id: str = "",
    related_entity: tuple | None = None,
    request_json: dict | None = None,
    target_is_pivot: bool = False,
) -> models.Job:
    """Create a job record in 'running' status and broadcast."""
    now = _now()
    job = models.Job(
        id=new_id("job"),
        pid=pid,
        type=job_type,
        status="running",
        title=title,
        target=target,
        command=command,
        created_by=created_by,
        connector_key=connector_key,
        operation=operation,
        scope_type=scope_type,
        scope_id=scope_id or pid,
        related_entity_type=(related_entity[0] if related_entity else ""),
        related_entity_id=(related_entity[1] if related_entity else ""),
        retry_of_job_id="",
        created_at=now,
        started_at=now,
        finished_at="",
        request_json=request_json or {},
        output="",
        error_output="",
        result_json={},
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    bcast(pid, "job", "create", _job_dict(job))
    try:
        check_engagement_rules(
            db,
            pid,
            target,
            connector_key,
            operation,
            command=command,
            target_is_pivot=target_is_pivot,
        )
    except EngagementViolation as exc:
        msg = str(exc)
        log_event(db, pid, created_by or None, "roe", "blocked", msg, {"target": target})
        finish_job(db, job, status="failed", error_output=f"Blocked by ROE/scope guard: {msg}")
        raise
    except ApprovalRequired as exc:
        # Held for ROE sign-off — not failed, not executed. A project admin
        # approves/rejects via the jobs API; approval re-queues it.
        job.status = "awaiting_approval"
        job.error_output = str(exc)
        db.commit()
        db.refresh(job)
        bcast(pid, "job", "update", _job_dict(job))
        log_event(
            db,
            pid,
            created_by or None,
            "roe",
            "awaiting_approval",
            str(exc),
            {"target": target, "job_id": job.id},
        )
        raise
    return job


def queue_job(
    db: Session,
    pid: str,
    job_type: str,
    title: str,
    *,
    target: str = "",
    command: str = "",
    created_by: str = "",
    connector_key: str = "",
    operation: str = "",
    scope: tuple[str, str] | None = None,
    related_entity: tuple | None = None,
    request_json: dict | None = None,
    retry_opts: dict | None = None,
) -> models.Job:
    _scope_type = scope[0] if scope else "project"
    _scope_id = (scope[1] if scope else "") or pid
    now = _now()
    job = models.Job(
        id=new_id("job"),
        pid=pid,
        type=job_type,
        status="queued",
        title=title,
        target=target,
        command=command,
        created_by=created_by,
        connector_key=connector_key,
        operation=operation,
        scope_type=_scope_type,
        scope_id=_scope_id,
        related_entity_type=(related_entity[0] if related_entity else ""),
        related_entity_id=(related_entity[1] if related_entity else ""),
        retry_of_job_id=retry_opts.get("retry_of_job_id", "") if retry_opts else "",
        priority=retry_opts.get("priority", 0) if retry_opts else 0,
        retry_count=retry_opts.get("retry_count", 0) if retry_opts else 0,
        max_retries=retry_opts.get("max_retries", 0) if retry_opts else 0,
        created_at=now,
        started_at="",
        finished_at="",
        request_json=request_json or {},
        output="",
        error_output="",
        result_json={},
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    bcast(pid, "job", "create", _job_dict(job))
    try:
        check_engagement_rules(db, pid, target, connector_key, operation, command=command)
    except EngagementViolation as exc:
        msg = str(exc)
        log_event(db, pid, created_by or None, "roe", "blocked", msg, {"target": target})
        # Unlike start_job, queue_job's callers don't execute anything
        # synchronously right after this returns — the job only actually
        # runs once run_queued_job() picks it up, and that function already
        # no-ops on any status other than "queued". So finishing it as
        # "failed" here (rather than raising) is enough to block execution,
        # and it keeps this violation on the same well-tested "failed job"
        # path playbook engines already handle, instead of risking an
        # unhandled exception inside a background asyncio task.
        finish_job(db, job, status="failed", error_output=f"Blocked by ROE/scope guard: {msg}")
    except ApprovalRequired as exc:
        # Held for ROE sign-off — stays a row, never picked up by
        # run_queued_job (status != "queued"), no exception into the
        # background task that called queue_job.
        job.status = "awaiting_approval"
        job.error_output = str(exc)
        db.commit()
        db.refresh(job)
        bcast(pid, "job", "update", _job_dict(job))
        log_event(
            db,
            pid,
            created_by or None,
            "roe",
            "awaiting_approval",
            str(exc),
            {"target": target, "job_id": job.id},
        )
    return job


def mark_job_running(db: Session, job: models.Job) -> models.Job:
    job.status = "running"
    if not job.started_at:
        job.started_at = _now()
    db.commit()
    db.refresh(job)
    bcast(job.pid, "job", "update", _job_dict(job))
    return job


def _notify_job_terminal(db: Session, job: "models.Job", status: str, error_output: str) -> None:
    try:
        from ..core.notifications import dispatch_sync

        title = f"Job {status}: {job.title or job.type}"
        body_text = f"Target: {job.target}" if job.target else f"Project: {job.pid}"
        if status == "failed" and error_output:
            body_text += f"\nError: {error_output[:200]}"
        dispatch_sync(db, f"job_{status}", title, body_text, {"job_id": job.id, "pid": job.pid})
    except Exception as e:
        logger.debug("job-terminal notification dispatch failed (job=%s): %s", job.id, e)


@contextmanager
def sync_job_scope(db: Session, job: models.Job):
    """Guard for SYNCHRONOUS jobs (start_job → inline work → finish_job in
    one request handler, e.g. the topology endpoints). An unhandled
    exception inside the block marks the job 'failed' with the error and
    re-raises — without this the job row stayed 'running' forever and only
    a backend restart could clear it (found live on a customer deployment:
    an eternal Smart Build spinner). HTTPException is passed through
    untouched — endpoints close their jobs explicitly on those paths."""
    try:
        yield
    except HTTPException:
        raise
    except Exception as exc:
        finish_job(db, job, status="failed", error_output=str(exc))
        raise


def finish_job(
    db: Session,
    job: models.Job,
    *,
    status: str = "done",
    output: str = "",
    error_output: str = "",
    result: dict | None = None,
) -> models.Job:
    """Update job to terminal status and broadcast."""
    # Re-read from DB under a row lock to detect external cancel that raced
    # with job completion. A plain refresh (no lock) left a window where a
    # concurrent cancel between this refresh and our commit below could still
    # be overwritten by this call's "done"/"failed" (security audit finding
    # F22) — with_for_update holds the row until our commit/rollback.
    db.refresh(job, with_for_update=True)
    if job.status == "cancelled" and status in ("done", "failed", "unconfirmed"):
        return job  # Cancel took priority; don't overwrite with done/failed/unconfirmed
    job.status = status
    job.output = output
    job.error_output = error_output
    job.result_json = result or {}
    job.finished_at = _now()
    db.commit()
    db.refresh(job)
    bcast(job.pid, "job", "update", _job_dict(job))

    # Auto-retry on failure if max_retries allows
    retry_count = getattr(job, "retry_count", 0) or 0
    max_retries = getattr(job, "max_retries", 0) or 0
    if status == "failed" and retry_count < max_retries:
        _schedule_auto_retry(db, job, retry_count)
        return job

    if status in ("done", "failed", "unconfirmed"):
        _notify_job_terminal(db, job, status, error_output)

    # Scan snapshot capture for diffing (both sync + async paths)
    if status == "done" and (job.connector_key or "") in (
        "nmap",
        "httpx",
        "netexec",
        "nuclei",
        "ffuf",
    ):
        try:
            from ..core.writeback import _capture_scan_snapshots

            _capture_scan_snapshots(db, job)
        except Exception:
            pass

    return job


def _schedule_auto_retry(db: Session, job: models.Job, current_retry_count: int) -> None:
    """Clone a failed job and re-queue it with exponential backoff."""
    import asyncio

    next_count = current_retry_count + 1
    backoff_seconds = min(30 * (2**current_retry_count), 300)  # 30s, 60s, 120s … max 5min

    retry_job = queue_job(
        db,
        job.pid,
        job.type,
        job.title,
        target=job.target,
        command=job.command,
        created_by=job.created_by,
        connector_key=job.connector_key,
        operation=job.operation,
        scope=(job.scope_type, job.scope_id),
        related_entity=(job.related_entity_type, job.related_entity_id),
        request_json=job.request_json or {},
        retry_opts={
            "retry_of_job_id": job.id,
            "priority": getattr(job, "priority", 0) or 0,
            "retry_count": next_count,
            "max_retries": getattr(job, "max_retries", 0) or 0,
        },
    )

    async def _delayed_submit(job_id: str, pid: str, priority: int, delay: float) -> None:
        await asyncio.sleep(delay)
        from .job_runner import schedule_job_run

        schedule_job_run(job_id, pid=pid, priority=priority)

    try:
        loop = asyncio.get_running_loop()
        loop.create_task(
            _delayed_submit(
                retry_job.id, job.pid, getattr(job, "priority", 0) or 0, float(backoff_seconds)
            )
        )
    except RuntimeError:
        # No running loop (e.g. tests) — submit immediately
        from .job_runner import schedule_job_run

        schedule_job_run(retry_job.id, pid=job.pid, priority=getattr(job, "priority", 0) or 0)

    import logging

    logging.getLogger(__name__).info(
        "Auto-retry %d/%d for job %s → new job %s (backoff %ds)",
        next_count,
        getattr(job, "max_retries", 0),
        job.id,
        retry_job.id,
        backoff_seconds,
    )
