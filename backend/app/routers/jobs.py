import asyncio
import json
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from sqlalchemy import or_
from sqlalchemy.orm import Session

from .. import models
from ..core import job_streams
from ..core.access import check_pid_access
from ..core.deps import get_current_user
from ..core.events import bcast
from ..core.job_runner import schedule_job_run, supports_queued_execution
from ..core.job_tracker import queue_job
from ..core.permissions import (
    PERM_COMMAND_OUTPUTS_CREATE,
    PERM_COMMAND_OUTPUTS_READ,
    PERM_PROJECT_MANAGE_MEMBERS,
)
from ..core.utils import ts_now
from ..database import get_db

router = APIRouter(
    prefix="/api/projects/{pid}/jobs",
    tags=["jobs"],
    responses={
        400: {"description": "Bad request"},
        404: {"description": "Not found"},
    },
)

_MSG_JOB_NOT_FOUND = "Job not found"


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
        "priority": getattr(job, "priority", 0) or 0,
        "retry_count": getattr(job, "retry_count", 0) or 0,
        "max_retries": getattr(job, "max_retries", 0) or 0,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "request_json": job.request_json or {},
        "result_json": job.result_json or {},
    }


def _clone_job_for_queue(
    db: Session, source: models.Job, *, created_by: str, retry_of_job_id: str = ""
) -> models.Job:
    return queue_job(
        db,
        source.pid,
        source.type,
        source.title,
        target=source.target,
        command=source.command,
        created_by=created_by,
        connector_key=source.connector_key,
        operation=source.operation,
        scope=(source.scope_type, source.scope_id),
        related_entity=(source.related_entity_type, source.related_entity_id),
        request_json=source.request_json or {},
        retry_opts={
            "retry_of_job_id": retry_of_job_id,
            "priority": getattr(source, "priority", 0) or 0,
            "max_retries": getattr(source, "max_retries", 0) or 0,
        },
    )


def _can_read_secret(db, pid, user) -> bool:
    """Security audit 2026-10-09 (M-4): the WS broadcast layer redacts job
    command/output for recipients without credentials.read_secret; the REST
    list and the SSE stream did not — same data, no redaction. Central
    check used by both surfaces below for parity."""
    from ..core.access import check_pid_access as _check
    from ..core.permissions import PERM_CREDENTIALS_READ_SECRET

    try:
        _check(db, pid, user, PERM_CREDENTIALS_READ_SECRET)
        return True
    except Exception:
        return False


def _job_out(job, can_read_secret: bool) -> dict:
    d = _job_dict(job)
    if not can_read_secret:
        d["command"] = ""
        d["output"] = ""
        d["error_output"] = ""
    return d

@router.get("")

def list_jobs(
    pid: str,
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    type: str | None = None,
    status: str | None = None,
    connector_key: str | None = None,
    playbook_run_id: str | None = None,
    output_search: str | None = None,
    limit: int = 200,
    offset: int = 0,
):
    check_pid_access(db, pid, user, PERM_COMMAND_OUTPUTS_READ)
    q = db.query(models.Job).filter(models.Job.pid == pid)
    if type:
        q = q.filter(models.Job.type == type)
    if status:
        q = q.filter(models.Job.status == status)
    if connector_key:
        q = q.filter(models.Job.connector_key == connector_key)
    if playbook_run_id:
        # Use jsonb @> (contains) instead of ->>'key' = value so the
        # jsonb_path_ops GIN index in migration 008 actually kicks in.
        q = q.filter(models.Job.request_json.contains({"playbook_run_id": playbook_run_id}))
    if output_search:
        pattern = f"%{output_search}%"
        q = q.filter(
            or_(
                models.Job.output.ilike(pattern),
                models.Job.error_output.ilike(pattern),
            )
        )
    total = q.count()
    response.headers["X-Total-Count"] = str(total)
    response.headers["Access-Control-Expose-Headers"] = "X-Total-Count"
    jobs = (
        q.order_by(models.Job.created_at.desc())
        .offset(max(0, offset))
        .limit(min(max(1, limit), 1000))
        .all()
    )
    can_secret = _can_read_secret(db, pid, user)
    return [_job_out(j, can_secret) for j in jobs]


@router.get("/chain-suggestions", responses={404: {"description": "Not found"}})
def get_chain_suggestions(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    job_id: str | None = None,
):
    """Return suggested next-step scan actions based on current host data."""
    check_pid_access(db, pid, user, "hosts.read")
    from ..core.chain_suggestions import suggest_chain_actions

    job = None
    if job_id:
        job = db.query(models.Job).filter(models.Job.id == job_id, models.Job.pid == pid).first()

    return suggest_chain_actions(db, pid, job=job)


@router.get("/{job_id}", responses={404: {"description": "Not found"}})
def get_job(
    pid: str,
    job_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, PERM_COMMAND_OUTPUTS_READ)
    job = db.query(models.Job).filter(models.Job.id == job_id, models.Job.pid == pid).first()
    if not job:
        raise HTTPException(404, _MSG_JOB_NOT_FOUND)
    return _job_out(job, _can_read_secret(db, pid, user))


@router.delete("/{job_id}", status_code=204, responses={404: {"description": "Not found"}})
def delete_job(
    pid: str,
    job_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, PERM_COMMAND_OUTPUTS_CREATE)
    job = db.query(models.Job).filter(models.Job.id == job_id, models.Job.pid == pid).first()
    if not job:
        raise HTTPException(404, _MSG_JOB_NOT_FOUND)
    db.delete(job)
    db.commit()
    bcast(pid, "job", "delete", {"id": job_id})


@router.patch(
    "/{job_id}/cancel",
    status_code=200,
    responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}},
)
async def cancel_job(
    pid: str,
    job_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, PERM_COMMAND_OUTPUTS_CREATE)
    job = db.query(models.Job).filter(models.Job.id == job_id, models.Job.pid == pid).first()
    if not job:
        raise HTTPException(404, _MSG_JOB_NOT_FOUND)
    if job.status not in ("queued", "running"):
        raise HTTPException(400, "Job is already in a terminal state")
    # Signal in-process worker to stop (no-op when WORKER_BACKEND=arq)
    from ..core.worker_pool import get_pool

    get_pool().cancel_job(job_id)
    # When running in arq mode, signal the worker process via Redis cancel key.
    import os as _os

    if _os.environ.get("WORKER_BACKEND", "").lower() == "arq":
        from ..core.arq_pool import get_arq_pool
        from ..core.arq_worker import CANCEL_KEY_PREFIX

        arq_pool = get_arq_pool()
        if arq_pool is not None:
            await arq_pool.set(f"{CANCEL_KEY_PREFIX}{job_id}", "1", ex=3600)
    # Optimistically mark cancelled in DB for both queued and running jobs.
    # finish_job() will skip overwriting if it sees "cancelled" already set.
    job.status = "cancelled"
    db.commit()
    db.refresh(job)
    bcast(pid, "job", "update", _job_dict(job))
    return _job_dict(job)


@router.post(
    "/{job_id}/rerun",
    status_code=201,
    responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}},
)
async def rerun_job(
    pid: str,
    job_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, PERM_COMMAND_OUTPUTS_CREATE)
    source = db.query(models.Job).filter(models.Job.id == job_id, models.Job.pid == pid).first()
    if not source:
        raise HTTPException(404, _MSG_JOB_NOT_FOUND)
    if source.status in ("queued", "running"):
        raise HTTPException(400, "Cannot rerun an active job")
    if not source.request_json:
        raise HTTPException(
            400, "This job cannot be rerun because no orchestration payload was stored"
        )
    if not supports_queued_execution(source.connector_key, source.operation):
        raise HTTPException(400, "Queued rerun is not supported for this connector/operation")
    cloned = _clone_job_for_queue(db, source, created_by=getattr(user, "username", "") or "")
    schedule_job_run(cloned.id, pid=pid, priority=10)
    return _job_dict(cloned)


@router.post(
    "/{job_id}/retry",
    status_code=201,
    responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}},
)
async def retry_job(
    pid: str,
    job_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, PERM_COMMAND_OUTPUTS_CREATE)
    source = db.query(models.Job).filter(models.Job.id == job_id, models.Job.pid == pid).first()
    if not source:
        raise HTTPException(404, _MSG_JOB_NOT_FOUND)
    if source.status not in ("failed", "cancelled"):
        raise HTTPException(400, "Retry is only available for failed or cancelled jobs")
    if not source.request_json:
        raise HTTPException(
            400, "This job cannot be retried because no orchestration payload was stored"
        )
    if not supports_queued_execution(source.connector_key, source.operation):
        raise HTTPException(400, "Queued retry is not supported for this connector/operation")
    cloned = _clone_job_for_queue(
        db, source, created_by=getattr(user, "username", "") or "", retry_of_job_id=source.id
    )
    schedule_job_run(cloned.id, pid=pid, priority=10)
    return _job_dict(cloned)


@router.post(
    "/{job_id}/approve",
    responses={
        400: {"description": "Bad request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)
def approve_job(
    pid: str,
    job_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    """Approve a job held by the ROE requires_approval gate.

    Only a project admin+ (project.manage_members) or a platform admin can
    approve. Approval re-checks the remaining engagement rules (work hours,
    scope, forbidden activities) and queues the job for execution.
    """
    check_pid_access(db, pid, user, PERM_PROJECT_MANAGE_MEMBERS)
    job = db.query(models.Job).filter(models.Job.id == job_id, models.Job.pid == pid).first()
    if not job:
        raise HTTPException(404, _MSG_JOB_NOT_FOUND)
    if job.status != "awaiting_approval":
        raise HTTPException(400, f"Job is not awaiting approval (status: {job.status})")

    from ..core.roe_guard import (
        EngagementViolation,
        check_roe_activities,
        check_roe_work_hours,
        check_target_scope,
    )

    try:
        # Re-verify everything EXCEPT the requires_approval gate this
        # endpoint is resolving: work hours / forbidden activities / scope
        # may still have changed (or been violated) since submission.
        check_roe_work_hours(db, pid)
        check_roe_activities(db, pid, job.connector_key, job.operation, check_requires=False)
        # exec-style jobs carry the SSH pivot in job.target — same pivot
        # exemption as at submission time (see roe_guard.check_engagement_rules)
        if not (job.connector_key == "attacker_ssh" and job.operation in ("exec", "bulk_exec")):
            check_target_scope(db, pid, job.target)
    except EngagementViolation as exc:
        job.status = "failed"
        job.error_output = f"Blocked by ROE/scope guard on approval: {exc}"
        db.commit()
        db.refresh(job)
        raise HTTPException(403, str(exc)) from exc

    from ..core.events import log_event

    job.status = "queued"
    job.error_output = ""
    db.commit()
    db.refresh(job)
    bcast(pid, "job", "update", _job_dict(job))
    log_event(
        db,
        pid,
        getattr(user, "username", None),
        "roe",
        "approved",
        f"Job {job.id} approved under ROE and queued for execution",
        {"job_id": job.id},
    )
    schedule_job_run(job.id, pid=pid, priority=10)

    # If this job is a step of a playbook run that survived a backend
    # restart while waiting for approval, its engine task is gone —
    # re-attach the run so it reaches a terminal state once this job
    # finishes (no-op when a live engine already owns the run).
    run_id = (job.request_json or {}).get("playbook_run_id")
    if run_id:
        from ..routers.playbooks._engine import schedule_run_resume_after_approval

        schedule_run_resume_after_approval(run_id, job.id)

    return _job_dict(job)


@router.post(
    "/{job_id}/reject",
    responses={
        400: {"description": "Bad request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)
def reject_job(
    pid: str,
    job_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    """Reject a job held by the ROE requires_approval gate."""
    check_pid_access(db, pid, user, PERM_PROJECT_MANAGE_MEMBERS)
    job = db.query(models.Job).filter(models.Job.id == job_id, models.Job.pid == pid).first()
    if not job:
        raise HTTPException(404, _MSG_JOB_NOT_FOUND)
    if job.status != "awaiting_approval":
        raise HTTPException(400, f"Job is not awaiting approval (status: {job.status})")

    from ..core.events import log_event

    note = job.error_output or ""
    job.status = "cancelled"
    job.error_output = f"Rejected under ROE by {getattr(user, 'username', user.id)}. {note}".strip()
    job.finished_at = ts_now()
    db.commit()
    db.refresh(job)
    bcast(pid, "job", "update", _job_dict(job))
    log_event(
        db,
        pid,
        getattr(user, "username", None),
        "roe",
        "rejected",
        f"Job {job.id} rejected under ROE",
        {"job_id": job.id},
    )
    return _job_dict(job)


# Emit ~every 10s of idle (0.3s poll * 33) so the connection never idles out
# through a proxy, and reconnects resume cleanly via Last-Event-ID.
_KEEPALIVE_TICKS = 33


async def _drain_job_stream(job, job_id: str, cursor: int):
    for line in job_streams.get_lines(job_id, cursor):
        cursor += 1
        yield f"id: {cursor}\ndata: {json.dumps({'line': line})}\n\n"
    if not job_streams.get_lines(job_id) and job.output:
        for line in job.output.splitlines():
            cursor += 1
            yield f"id: {cursor}\ndata: {json.dumps({'line': line})}\n\n"
    yield f"data: {json.dumps({'done': True, 'status': job.status})}\n\n"
    job_streams.cleanup_expired()


async def _generate_job_stream(job, job_id: str, db, cursor: int = 0, redact: bool = False):
    """SSE generator. `cursor` = number of lines already delivered (from a
    Last-Event-ID on reconnect), so a dropped connection resumes without
    replaying — or duplicating — output. Each line carries an `id:` (the new
    cursor) and idle keepalive comments keep the stream alive through proxies."""
    idle = 0
    while True:
        lines = job_streams.get_lines(job_id, cursor)
        for line in lines:
            cursor += 1
            payload_line = "[redacted: requires credentials.read_secret]" if redact else line
            yield f"id: {cursor}\ndata: {json.dumps({'line': payload_line})}\n\n"
        if lines:
            idle = 0
        else:
            idle += 1
            if idle >= _KEEPALIVE_TICKS:
                idle = 0
                yield ": keepalive\n\n"
        db.expire(job)
        db.refresh(job)
        closed = job_streams.is_closed(job_id)
        terminal = job.status in ("done", "failed", "cancelled", "unconfirmed")
        if closed or terminal:
            async for item in _drain_job_stream(job, job_id, cursor):
                yield item
            return
        await asyncio.sleep(0.3)


@router.get("/{job_id}/output-stream", responses={404: {"description": "Not found"}})
async def stream_job_output(
    pid: str,
    job_id: str,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    """SSE endpoint streaming live job output line by line. Honours
    Last-Event-ID so a reconnect (proxy timeout, network blip) resumes from
    where it left off instead of replaying the whole log."""
    check_pid_access(db, pid, user, PERM_COMMAND_OUTPUTS_READ)
    job = db.query(models.Job).filter(models.Job.id == job_id, models.Job.pid == pid).first()
    if not job:
        raise HTTPException(404, _MSG_JOB_NOT_FOUND)

    try:
        cursor = max(0, int(request.headers.get("last-event-id") or 0))
    except ValueError:
        cursor = 0

    can_secret = _can_read_secret(db, pid, user)
    return StreamingResponse(
        _generate_job_stream(job, job_id, db, cursor, redact=not can_secret),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@router.get("/{job_id}/artifacts", responses={404: {"description": "Not found"}})
def list_job_artifacts(
    pid: str,
    job_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    """Return all Loot records auto-extracted or linked to this job."""
    check_pid_access(db, pid, user, "loot.read")
    job = db.query(models.Job).filter(models.Job.id == job_id, models.Job.pid == pid).first()
    if not job:
        raise HTTPException(404, _MSG_JOB_NOT_FOUND)
    loots = (
        db.query(models.Loot)
        .filter(
            models.Loot.pid == pid,
            models.Loot.job_id == job_id,
        )
        .order_by(models.Loot.ts.desc())
        .all()
    )
    from .. import schemas

    return [schemas.Loot.model_validate(loot).model_dump() for loot in loots]
