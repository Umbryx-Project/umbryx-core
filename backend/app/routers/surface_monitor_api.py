"""Continuous attack-surface monitoring — project watch CRUD + manual run."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import models
from ..core.access import check_pid_access
from ..core.deps import get_current_user
from ..core.surface_monitor import _run_watch_sync
from ..core.utils import new_id, ts_now
from ..database import get_db
from ..models.surface_watch import SurfaceWatch

router = APIRouter(prefix="/api/projects/{pid}/watch", tags=["surface-watch"])


class WatchBody(BaseModel):
    name: str = Field("Surface watch", max_length=200)
    interval_minutes: int = Field(60, ge=5, le=10080)
    targets: str = Field("", max_length=2000)  # empty = project scope CIDRs
    intensity_profile: str = "normal"
    enabled: bool = True


class WatchPatch(BaseModel):
    name: str | None = None
    interval_minutes: int | None = Field(None, ge=5, le=10080)
    targets: str | None = None
    intensity_profile: str | None = None
    enabled: bool | None = None


@router.get("")
def list_watches(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "hosts.read")
    return (
        db.query(SurfaceWatch)
        .filter(SurfaceWatch.pid == pid)
        .order_by(SurfaceWatch.created_at.desc())
        .all()
    )


@router.post("", status_code=201)
def create_watch(
    pid: str,
    body: WatchBody,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "hosts.create")
    w = SurfaceWatch(
        id=new_id("sw"),
        pid=pid,
        name=body.name,
        interval_minutes=body.interval_minutes,
        targets=body.targets,
        intensity_profile=body.intensity_profile,
        enabled=body.enabled,
        created_by=user.id,
        created_at=ts_now(),
    )
    db.add(w)
    db.commit()
    db.refresh(w)
    return w


@router.patch("/{wid}")
def update_watch(
    pid: str,
    wid: str,
    body: WatchPatch,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "hosts.create")
    w = db.query(SurfaceWatch).filter(SurfaceWatch.id == wid, SurfaceWatch.pid == pid).first()
    if not w:
        raise HTTPException(404)
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(w, field, value)
    db.commit()
    db.refresh(w)
    return w


@router.delete("/{wid}", status_code=204)
def delete_watch(
    pid: str,
    wid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "hosts.create")
    w = db.query(SurfaceWatch).filter(SurfaceWatch.id == wid, SurfaceWatch.pid == pid).first()
    if not w:
        raise HTTPException(404)
    db.delete(w)
    db.commit()


@router.post("/{wid}/run", status_code=202)
def run_watch_now(
    pid: str,
    wid: str,
    background_tasks: BackgroundTasks,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "hosts.create")
    w = db.query(SurfaceWatch).filter(SurfaceWatch.id == wid, SurfaceWatch.pid == pid).first()
    if not w:
        raise HTTPException(404)
    if w.state == "running":
        raise HTTPException(409, "Watch run already in progress")
    w.state = "running"
    db.commit()
    from ..core.utils import spawn_background

    spawn_background(_run_watch_sync, w.id, background_tasks=background_tasks)
    return {"status": "started"}
