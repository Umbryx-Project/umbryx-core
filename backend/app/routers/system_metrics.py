"""
Phase 1.5 — System metrics, worker info, and infrastructure health endpoints.
Guarded by require_admin (devops / platform_admin / admin).
"""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from .. import models
from ..core.deps import require_admin
from ..core.utils import ts_now
from ..database import get_db

router = APIRouter(
    prefix="/api/system",
    tags=["system"],
    responses={403: {"description": "Forbidden"}},
)


@router.get("/metrics")
def system_metrics(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(require_admin)],
):
    now = ts_now()
    job_status_counts = {}
    rows = db.query(models.Job.status, func.count(models.Job.id)).group_by(models.Job.status).all()
    for status, count in rows:
        job_status_counts[status or "unknown"] = count

    job_type_counts = {}
    rows = (
        db.query(models.Job.connector_key, func.count(models.Job.id))
        .group_by(models.Job.connector_key)
        .all()
    )
    for ck, count in rows:
        job_type_counts[ck or "unknown"] = count

    total_projects = db.query(models.Project).count()
    total_users = db.query(models.User).filter(models.User.active).count()
    total_hosts = db.query(models.Host).count()
    total_findings = db.query(models.Finding).count()

    return {
        "ts": now,
        "job_status_counts": job_status_counts,
        "job_type_counts": job_type_counts,
        "total_projects": total_projects,
        "total_users": total_users,
        "total_hosts": total_hosts,
        "total_findings": total_findings,
    }


@router.get("/workers")
def system_workers(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(require_admin)],
):
    running_jobs = (
        db.query(models.Job)
        .filter(
            models.Job.status.in_(["queued", "running"]),
        )
        .all()
    )
    workers = []
    for job in running_jobs:
        workers.append(
            {
                "job_id": job.id,
                "project_id": job.pid,
                "connector": job.connector_key or "unknown",
                "status": job.status,
                "started_at": getattr(job, "started_at", None) or getattr(job, "created_at", None),
            }
        )
    return {
        "active_workers": len(workers),
        "workers": workers,
    }


@router.get("/infra-health")
def system_infra_health(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(require_admin)],
):
    project_status_counts = {}
    rows = (
        db.query(models.Project.status, func.count(models.Project.id))
        .group_by(models.Project.status)
        .all()
    )
    for status, count in rows:
        project_status_counts[status or "unknown"] = count

    member_role_counts = {}
    rows = (
        db.query(models.ProjectMember.role, func.count(models.ProjectMember.id))
        .filter(
            models.ProjectMember.is_active,
        )
        .group_by(models.ProjectMember.role)
        .all()
    )
    for role, count in rows:
        member_role_counts[role or "unknown"] = count

    cred_type_counts = {}
    rows = db.query(models.Cred.type, func.count(models.Cred.id)).group_by(models.Cred.type).all()
    for ctype, count in rows:
        cred_type_counts[ctype or "unknown"] = count

    system_log_count = db.query(models.SystemLog).count()

    return {
        "ts": ts_now(),
        "project_status_counts": project_status_counts,
        "member_role_counts": member_role_counts,
        "cred_type_counts": cred_type_counts,
        "system_log_count": system_log_count,
    }
