from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models
from ..core.closure import archive_project, can_transition, close_project
from ..core.deps import require_admin
from ..database import get_db

router = APIRouter(prefix="/api/projects/{pid}", tags=["project-closure"])


def _report_to_dict(r: models.DecommissionReport):
    return {
        "id": r.id,
        "project_id": r.project_id,
        "closed_by": r.closed_by,
        "closure_started_at": r.closure_started_at,
        "closure_completed_at": r.closure_completed_at,
        "infra_destroyed": r.infra_destroyed,
        "secrets_revoked": r.secrets_revoked,
        "members_deactivated": r.members_deactivated,
        "export_bundle_hash": r.export_bundle_hash,
        "warnings": r.warnings,
        "final_status": r.final_status,
        "pdf_path": r.pdf_path,
    }


@router.post("/close")
async def project_close(
    pid: str,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404)
    try:
        report = await close_project(pid, user.id, db)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return _report_to_dict(report)


@router.post("/archive")
async def project_archive(
    pid: str,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    try:
        project = archive_project(pid, db)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {
        "id": project.id,
        "status": project.status,
        "closed_at": project.closed_at,
        "archived_at": project.archived_at,
    }


@router.get("/decommission-report")
async def get_decommission_report(
    pid: str,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    report = (
        db.query(models.DecommissionReport)
        .filter(models.DecommissionReport.project_id == pid)
        .order_by(models.DecommissionReport.closure_started_at.desc())
        .first()
    )
    if not report:
        raise HTTPException(404, "No decommission report found")
    return _report_to_dict(report)


@router.get("/closure-preview")
async def closure_preview(
    pid: str,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404)

    running_jobs = (
        db.query(models.Job)
        .filter(
            models.Job.pid == pid,
            models.Job.status.in_(["queued", "running"]),
        )
        .count()
    )

    open_findings = (
        db.query(models.Finding)
        .filter(
            models.Finding.pid == pid,
            models.Finding.status.in_(["open", "new"]),
        )
        .count()
    )

    infra_instances = 0
    try:
        from ..models.infra_v2 import InfraStack

        infra_instances = (
            db.query(InfraStack)
            .filter(
                InfraStack.project_id == pid,
                InfraStack.status.notin_(["destroyed", "tearing_down"]),
            )
            .count()
        )
    except Exception:
        pass

    active_members = (
        db.query(models.ProjectMember)
        .filter(
            models.ProjectMember.project_id == pid,
            models.ProjectMember.is_active.is_(True),
        )
        .count()
    )

    active_secrets = 0
    try:
        active_secrets = (
            db.query(models.ProjectSecret)
            .filter(
                models.ProjectSecret.project_id == pid,
                models.ProjectSecret.revoked_at.is_(None),
            )
            .count()
        )
    except Exception:
        pass

    return {
        "project_id": pid,
        "project_status": project.status,
        "can_close": can_transition(project.status, "closing"),
        "running_jobs": running_jobs,
        "open_findings": open_findings,
        "active_infra_instances": infra_instances,
        "active_members": active_members,
        "active_secrets": active_secrets,
    }
