from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.access import check_object_access, check_pid_access
from ..core.attack_metrics import collect_metrics
from ..core.deps import get_current_user
from ..core.permissions import PERM_ATTACK_PATHS_READ, PERM_ATTACK_PATHS_UPDATE
from ..core.utils import new_id, ts_now
from ..database import get_db

router = APIRouter(tags=["tasks"])


@router.get("/api/metrics")
def get_metrics(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    pid: str | None = None,
    scope: str = "local",
):
    if pid:
        check_pid_access(db, pid, user, PERM_ATTACK_PATHS_READ)
        collect_metrics(db, pid)
        q = (
            db.query(models.MetricSnapshot)
            .filter(
                models.MetricSnapshot.pid == pid,
                models.MetricSnapshot.scope == scope,
            )
            .order_by(models.MetricSnapshot.captured_at.desc())
        )
        return [
            {
                "id": s.id,
                "pid": s.pid,
                "scope": s.scope,
                "metric_key": s.metric_key,
                "value": s.value,
                "dims": s.dims,
                "captured_at": s.captured_at,
            }
            for s in q.all()
        ]
    return []


@router.get("/api/tasks", response_model=list[schemas.Task])
def list_tasks(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    pid: str | None = None,
    status: str | None = None,
    assignee: str | None = None,
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    if pid:
        check_pid_access(db, pid, user, PERM_ATTACK_PATHS_READ)
        q = db.query(models.Task).filter(models.Task.pid == pid, models.Task.deleted_at.is_(None))
        if status:
            q = q.filter(models.Task.status == status)
        if assignee:
            q = q.filter(models.Task.assignee == assignee)
        total = q.count()
        response.headers["X-Total-Count"] = str(total)
        return q.order_by(models.Task.ts).offset(offset).limit(limit).all()
    raise HTTPException(400, "pid is required")


@router.post("/api/tasks", response_model=schemas.Task)
def create_task(
    body: schemas.TaskCreate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, body.pid, user, PERM_ATTACK_PATHS_UPDATE)
    obj = models.Task(
        **body.model_dump(),
        id=new_id("tsk"),
        created_by=user.id,
        ts=ts_now(),
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


@router.patch("/api/tasks/{task_id}", response_model=schemas.Task)
def update_task(
    task_id: str,
    body: schemas.TaskUpdate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    obj = (
        db.query(models.Task)
        .filter(models.Task.id == task_id, models.Task.deleted_at.is_(None))
        .first()
    )
    if not obj:
        raise HTTPException(404)
    check_object_access(db, obj.pid, user, PERM_ATTACK_PATHS_UPDATE)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(obj, k, v)
    db.commit()
    db.refresh(obj)
    return obj


@router.delete("/api/tasks/{task_id}")
def delete_task(
    task_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    obj = (
        db.query(models.Task)
        .filter(models.Task.id == task_id, models.Task.deleted_at.is_(None))
        .first()
    )
    if not obj:
        raise HTTPException(404)
    check_object_access(db, obj.pid, user, PERM_ATTACK_PATHS_UPDATE)
    obj.deleted_at = ts_now()
    db.commit()
    return {"ok": True}


@router.get("/api/remediations", response_model=list[schemas.Remediation])
def list_remediations(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    pid: str | None = None,
    finding_id: str | None = None,
    status: str | None = None,
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    if pid:
        check_pid_access(db, pid, user, PERM_ATTACK_PATHS_READ)
        q = db.query(models.Remediation).filter(
            models.Remediation.pid == pid, models.Remediation.deleted_at.is_(None)
        )
        if finding_id:
            q = q.filter(models.Remediation.finding_id == finding_id)
        if status:
            q = q.filter(models.Remediation.status == status)
        total = q.count()
        response.headers["X-Total-Count"] = str(total)
        return q.order_by(models.Remediation.ts).offset(offset).limit(limit).all()
    raise HTTPException(400, "pid is required")


@router.post("/api/remediations", response_model=schemas.Remediation)
def create_remediation(
    body: schemas.RemediationCreate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, body.pid, user, PERM_ATTACK_PATHS_UPDATE)
    obj = models.Remediation(
        **body.model_dump(),
        id=new_id("rem"),
        created_by=user.id,
        ts=ts_now(),
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


@router.patch("/api/remediations/{rem_id}", response_model=schemas.Remediation)
def update_remediation(
    rem_id: str,
    body: schemas.RemediationUpdate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    obj = (
        db.query(models.Remediation)
        .filter(models.Remediation.id == rem_id, models.Remediation.deleted_at.is_(None))
        .first()
    )
    if not obj:
        raise HTTPException(404)
    check_object_access(db, obj.pid, user, PERM_ATTACK_PATHS_UPDATE)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(obj, k, v)
    db.commit()
    db.refresh(obj)
    return obj


@router.delete("/api/remediations/{rem_id}")
def delete_remediation(
    rem_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    obj = (
        db.query(models.Remediation)
        .filter(models.Remediation.id == rem_id, models.Remediation.deleted_at.is_(None))
        .first()
    )
    if not obj:
        raise HTTPException(404)
    check_object_access(db, obj.pid, user, PERM_ATTACK_PATHS_UPDATE)
    obj.deleted_at = ts_now()
    db.commit()
    return {"ok": True}


@router.get("/api/evidence", response_model=list[schemas.Evidence])
def list_evidence(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    pid: str | None = None,
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    if pid:
        check_pid_access(db, pid, user, PERM_ATTACK_PATHS_READ)
        q = db.query(models.Evidence).filter(models.Evidence.pid == pid)
        total = q.count()
        response.headers["X-Total-Count"] = str(total)
        return q.order_by(models.Evidence.ts).offset(offset).limit(limit).all()
    raise HTTPException(400, "pid is required")


@router.post("/api/evidence", response_model=schemas.Evidence)
def create_evidence(
    body: schemas.EvidenceCreate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, body.pid, user, PERM_ATTACK_PATHS_UPDATE)
    obj = models.Evidence(
        **body.model_dump(),
        id=new_id("evi"),
        created_by=user.id,
        ts=ts_now(),
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


@router.delete("/api/evidence/{evi_id}")
def delete_evidence(
    evi_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    obj = db.query(models.Evidence).filter(models.Evidence.id == evi_id).first()
    if not obj:
        raise HTTPException(404)
    check_object_access(db, obj.pid, user, PERM_ATTACK_PATHS_UPDATE)
    db.delete(obj)
    db.commit()
    return {"ok": True}


@router.get("/api/identities", response_model=list[schemas.Identity])
def list_identities(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    pid: str | None = None,
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    if pid:
        check_pid_access(db, pid, user, PERM_ATTACK_PATHS_READ)
        q = db.query(models.Identity).filter(
            models.Identity.pid == pid, models.Identity.deleted_at.is_(None)
        )
        total = q.count()
        response.headers["X-Total-Count"] = str(total)
        return q.order_by(models.Identity.ts).offset(offset).limit(limit).all()
    raise HTTPException(400, "pid is required")


@router.post("/api/identities", response_model=schemas.Identity)
def create_identity(
    body: schemas.IdentityCreate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, body.pid, user, PERM_ATTACK_PATHS_UPDATE)
    obj = models.Identity(
        **body.model_dump(),
        id=new_id("idn"),
        created_by=user.id,
        ts=ts_now(),
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj


@router.patch("/api/identities/{idn_id}", response_model=schemas.Identity)
def update_identity(
    idn_id: str,
    body: schemas.IdentityUpdate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    obj = (
        db.query(models.Identity)
        .filter(models.Identity.id == idn_id, models.Identity.deleted_at.is_(None))
        .first()
    )
    if not obj:
        raise HTTPException(404)
    check_object_access(db, obj.pid, user, PERM_ATTACK_PATHS_UPDATE)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(obj, k, v)
    db.commit()
    db.refresh(obj)
    return obj


@router.delete("/api/identities/{idn_id}")
def delete_identity(
    idn_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    obj = (
        db.query(models.Identity)
        .filter(models.Identity.id == idn_id, models.Identity.deleted_at.is_(None))
        .first()
    )
    if not obj:
        raise HTTPException(404)
    check_object_access(db, obj.pid, user, PERM_ATTACK_PATHS_UPDATE)
    obj.deleted_at = ts_now()
    db.commit()
    return {"ok": True}
