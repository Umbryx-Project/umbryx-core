from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.access import (
    check_object_access,
    check_pid_access,
    get_user_member_pids,
    require_attack_path_in_project,
)
from ..core.deps import get_current_user, is_admin
from ..core.events import bcast, log_event
from ..core.permissions import PERM_ATTACK_PATHS_READ, PERM_ATTACK_PATHS_UPDATE
from ..core.utils import new_id, ts_now
from ..database import get_db


def _step_to_dict(step):
    return schemas.AttackStep.model_validate(step).model_dump()


router = APIRouter(
    tags=["attack-paths"],
    responses={
        404: {"description": "Not found"},
    },
)


@router.get("/api/attack-paths", response_model=list[schemas.AttackPath])
def list_attack_paths(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    pid: str | None = None,
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    if pid:
        check_pid_access(db, pid, user, PERM_ATTACK_PATHS_READ)
        q = db.query(models.AttackPath).filter(models.AttackPath.pid == pid)
        total = q.count()
        response.headers["X-Total-Count"] = str(total)
        return q.order_by(models.AttackPath.ts).offset(offset).limit(limit).all()
    if is_admin(user):
        q = db.query(models.AttackPath)
        total = q.count()
        response.headers["X-Total-Count"] = str(total)
        return q.order_by(models.AttackPath.ts).offset(offset).limit(limit).all()
    member_pids = get_user_member_pids(db, user)
    q = db.query(models.AttackPath).filter(models.AttackPath.pid.in_(member_pids))
    total = q.count()
    response.headers["X-Total-Count"] = str(total)
    return q.order_by(models.AttackPath.ts).offset(offset).limit(limit).all()


@router.post("/api/attack-paths", response_model=schemas.AttackPath)
def create_attack_path(
    body: schemas.AttackPathCreate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, body.pid, user, PERM_ATTACK_PATHS_UPDATE)
    ap = models.AttackPath(**body.model_dump(), id=new_id("ap"), ts=ts_now())
    db.add(ap)
    log_event(
        db,
        ap.pid,
        getattr(request.state, "username", None),
        "attack_path",
        "create",
        f"Attack path created: {ap.name}",
    )
    db.commit()
    db.refresh(ap)
    bcast(ap.pid, "attack_path", "create", schemas.AttackPath.model_validate(ap).model_dump())
    return ap


@router.patch(
    "/api/attack-paths/{ap_id}",
    response_model=schemas.AttackPath,
    responses={404: {"description": "Not found"}},
)
def update_attack_path(
    ap_id: str,
    body: schemas.AttackPathUpdate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    ap = db.query(models.AttackPath).filter(models.AttackPath.id == ap_id).first()
    if not ap:
        raise HTTPException(404)
    check_object_access(db, ap.pid, user, PERM_ATTACK_PATHS_UPDATE)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(ap, k, v)
    ap.updated_at = ts_now()
    db.commit()
    db.refresh(ap)
    bcast(ap.pid, "attack_path", "update", schemas.AttackPath.model_validate(ap).model_dump())
    return ap


@router.delete("/api/attack-paths/{ap_id}", responses={404: {"description": "Not found"}})
def delete_attack_path(
    ap_id: str,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    ap = db.query(models.AttackPath).filter(models.AttackPath.id == ap_id).first()
    if not ap:
        raise HTTPException(404)
    check_object_access(db, ap.pid, user, PERM_ATTACK_PATHS_UPDATE)
    pid = ap.pid
    log_event(
        db,
        pid,
        getattr(request.state, "username", None),
        "attack_path",
        "delete",
        f"Attack path deleted: {ap.name}",
    )
    db.delete(ap)
    db.commit()
    bcast(pid, "attack_path", "delete", {"id": ap_id})
    return {"ok": True}


@router.get("/api/attack-steps", response_model=list[schemas.AttackStep])
def list_attack_steps(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    path_id: str | None = None,
    pid: str | None = None,
    parent_step_id: str | None = None,
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    if path_id:
        ap = db.query(models.AttackPath).filter(models.AttackPath.id == path_id).first()
        if not ap:
            return []
        check_object_access(db, ap.pid, user, PERM_ATTACK_PATHS_READ)
        q = db.query(models.AttackStep).filter(models.AttackStep.path_id == path_id)
        if parent_step_id is not None:
            q = q.filter(models.AttackStep.parent_step_id == (parent_step_id or None))
        total = q.count()
        response.headers["X-Total-Count"] = str(total)
        return q.order_by(models.AttackStep.step_order).offset(offset).limit(limit).all()
    if pid:
        check_pid_access(db, pid, user, PERM_ATTACK_PATHS_READ)
        q = db.query(models.AttackStep).filter(models.AttackStep.pid == pid)
        if parent_step_id is not None:
            q = q.filter(models.AttackStep.parent_step_id == (parent_step_id or None))
        total = q.count()
        response.headers["X-Total-Count"] = str(total)
        return q.order_by(models.AttackStep.step_order).offset(offset).limit(limit).all()
    if is_admin(user):
        q = db.query(models.AttackStep)
        total = q.count()
        response.headers["X-Total-Count"] = str(total)
        return q.order_by(models.AttackStep.step_order).offset(offset).limit(limit).all()
    member_pids = get_user_member_pids(db, user)
    q = db.query(models.AttackStep).filter(models.AttackStep.pid.in_(member_pids))
    total = q.count()
    response.headers["X-Total-Count"] = str(total)
    return q.order_by(models.AttackStep.step_order).offset(offset).limit(limit).all()


@router.post("/api/attack-steps", response_model=schemas.AttackStep)
def create_attack_step(
    body: schemas.AttackStepCreate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, body.pid, user, PERM_ATTACK_PATHS_UPDATE)
    require_attack_path_in_project(db, body.path_id, body.pid)
    step = models.AttackStep(**body.model_dump(), id=new_id("as"), ts=ts_now())
    db.add(step)
    db.commit()
    db.refresh(step)
    bcast(step.pid, "attack_step", "create", schemas.AttackStep.model_validate(step).model_dump())
    return step


@router.patch(
    "/api/attack-steps/{step_id}",
    response_model=schemas.AttackStep,
    responses={404: {"description": "Not found"}},
)
def update_attack_step(
    step_id: str,
    body: schemas.AttackStepUpdate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    step = db.query(models.AttackStep).filter(models.AttackStep.id == step_id).first()
    if not step:
        raise HTTPException(404)
    check_object_access(db, step.pid, user, PERM_ATTACK_PATHS_UPDATE)
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(step, k, v)
    db.commit()
    db.refresh(step)
    bcast(step.pid, "attack_step", "update", schemas.AttackStep.model_validate(step).model_dump())
    return step


@router.delete("/api/attack-steps/{step_id}", responses={404: {"description": "Not found"}})
def delete_attack_step(
    step_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    step = db.query(models.AttackStep).filter(models.AttackStep.id == step_id).first()
    if not step:
        raise HTTPException(404)
    check_object_access(db, step.pid, user, PERM_ATTACK_PATHS_UPDATE)
    pid = step.pid
    db.delete(step)
    db.commit()
    bcast(pid, "attack_step", "delete", {"id": step_id})
    return {"ok": True}


@router.post("/api/attack-steps/{step_id}/move")
def move_step(
    step_id: str,
    body: dict,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    step = db.query(models.AttackStep).filter(models.AttackStep.id == step_id).first()
    if not step:
        raise HTTPException(404, "Step not found")
    check_object_access(db, step.pid, user, PERM_ATTACK_PATHS_UPDATE)
    new_parent_id = body.get("parent_step_id")
    new_order = body.get("step_order")
    if new_parent_id is not None:
        if new_parent_id == step_id:
            raise HTTPException(400, "Cannot set self as parent")
        # Security audit 2026-10-09 (LOW): the new parent must live in the
        # same project — a foreign step id used to re-parent cross-project.
        if new_parent_id:
            parent = (
                db.query(models.AttackStep).filter(models.AttackStep.id == new_parent_id).first()
            )
            if not parent or parent.pid != step.pid:
                raise HTTPException(404, "Parent step not found in this project")
        step.parent_step_id = new_parent_id if new_parent_id else None
    if new_order is not None:
        step.step_order = new_order
    step.ts = ts_now()
    db.commit()
    db.refresh(step)
    bcast(step.pid, "attack_step", "update", _step_to_dict(step))
    return _step_to_dict(step)
