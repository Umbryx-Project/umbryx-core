"""
Rules of Engagement (ROE) API — per-project operational constraints.
"""

from typing import Annotated

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models
from ..core.access import check_pid_access
from ..core.deps import get_current_user, is_admin
from ..core.events import log_event
from ..core.utils import new_id, ts_now
from ..database import get_db

router = APIRouter(
    prefix="/api/projects/{pid}/roe",
    tags=["roe"],
    responses={
        400: {"description": "Bad request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)


class ROEBody(BaseModel):
    allowed_activities: list[str] = []
    forbidden_activities: list[str] = []
    work_hours_start: str | None = None
    work_hours_end: str | None = None
    timezone: str = "UTC"
    max_scan_rate: str | None = None
    requires_approval: list[str] = []
    emergency_contacts: list[dict] = []
    notes: str = ""


class ROEOut(BaseModel):
    id: str
    project_id: str
    allowed_activities: list[str]
    forbidden_activities: list[str]
    work_hours_start: str | None
    work_hours_end: str | None
    timezone: str
    max_scan_rate: str | None
    requires_approval: list[str]
    emergency_contacts: list[dict]
    notes: str
    updated_at: str
    updated_by: str | None


@router.get("", response_model=ROEOut)
def get_roe(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "project.read")
    roe = db.query(models.ProjectROE).filter(models.ProjectROE.project_id == pid).first()
    if not roe:
        return ROEOut(
            id="",
            project_id=pid,
            allowed_activities=[],
            forbidden_activities=[],
            work_hours_start=None,
            work_hours_end=None,
            timezone="UTC",
            max_scan_rate=None,
            requires_approval=[],
            emergency_contacts=[],
            notes="",
            updated_at=ts_now(),
            updated_by=None,
        )
    return roe


@router.put("", response_model=ROEOut)
def upsert_roe(
    pid: str,
    body: ROEBody,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    if not is_admin(user):
        check_pid_access(db, pid, user, "project.manage_members")
    roe = db.query(models.ProjectROE).filter(models.ProjectROE.project_id == pid).first()
    if roe:
        roe.allowed_activities = body.allowed_activities
        roe.forbidden_activities = body.forbidden_activities
        roe.work_hours_start = body.work_hours_start
        roe.work_hours_end = body.work_hours_end
        roe.timezone = body.timezone
        roe.max_scan_rate = body.max_scan_rate
        roe.requires_approval = body.requires_approval
        roe.emergency_contacts = body.emergency_contacts
        roe.notes = body.notes
        roe.updated_at = ts_now()
        roe.updated_by = user.id
    else:
        roe = models.ProjectROE(
            id=new_id("roe"),
            project_id=pid,
            allowed_activities=body.allowed_activities,
            forbidden_activities=body.forbidden_activities,
            work_hours_start=body.work_hours_start,
            work_hours_end=body.work_hours_end,
            timezone=body.timezone,
            max_scan_rate=body.max_scan_rate,
            requires_approval=body.requires_approval,
            emergency_contacts=body.emergency_contacts,
            notes=body.notes,
            updated_at=ts_now(),
            updated_by=user.id,
        )
        db.add(roe)
    log_event(
        db,
        pid,
        getattr(user, "username", None),
        "roe",
        "update",
        f"ROE updated: {len(body.allowed_activities)} allowed, {len(body.forbidden_activities)} forbidden",
        {"allowed": body.allowed_activities, "forbidden": body.forbidden_activities},
    )
    db.commit()
    db.refresh(roe)
    return roe


@router.delete("", status_code=204)
def delete_roe(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    if not is_admin(user):
        check_pid_access(db, pid, user, "project.manage_members")
    roe = db.query(models.ProjectROE).filter(models.ProjectROE.project_id == pid).first()
    if roe:
        log_event(db, pid, getattr(user, "username", None), "roe", "delete", "ROE deleted")
        db.delete(roe)
        db.commit()
