from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.access import check_object_access, check_pid_access, get_user_member_pids
from ..core.deps import get_current_user, is_admin
from ..core.events import bcast, log_event
from ..core.permissions import PERM_SCOPES_UPDATE
from ..core.utils import new_id, sync_project_ip_from_scopes
from ..database import get_db

router = APIRouter(prefix="/api/scopes", tags=["scopes"])


@router.post(
    "/extension-request",
    status_code=201,
    responses={
        400: {"description": "Bad request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)
def request_scope_extension(
    body: dict,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    """Operator-facing follow-up action for a ROE/scope block.

    A job blocked by the scope gate offers "request scope extension" in the
    UI; this endpoint notifies the project's admins (members who can change
    the scope) instead of letting the operator widen the engagement boundary
    unilaterally. The scope itself is NOT modified here.
    """
    from pydantic import BaseModel

    class _Body(BaseModel):
        pid: str
        value: str
        reason: str = ""
        blocked_job_id: str | None = None

    try:
        parsed = _Body(**{k: v for k, v in body.items() if k in _Body.model_fields})
    except Exception as exc:
        raise HTTPException(400, f"Invalid request: {exc}") from exc
    if not parsed.pid or not parsed.value.strip():
        raise HTTPException(400, "pid and value are required")
    # Any project member may ask for an extension; approvers are admins.
    check_pid_access(db, parsed.pid, user)

    from ..core.notify import push_notification
    from ..core.permissions import get_permissions_for_role

    recipients = []
    members = (
        db.query(models.ProjectMember)
        .filter(models.ProjectMember.project_id == parsed.pid, models.ProjectMember.is_active)
        .all()
    )
    for m in members:
        if "scopes.update" in get_permissions_for_role(m.role):
            recipients.append(m.user_id)
    platform_admins = db.query(models.User).filter(models.User.role == "platform_admin").all()
    recipient_ids = set(recipients) | {u.id for u in platform_admins}

    who = getattr(user, "username", "") or user.id
    title = "Scope extension requested"
    body_text = (
        f"{who} requests adding {parsed.value.strip()} to the project scope.\n"
        f"Reason: {parsed.reason.strip() or 'not provided'}."
    )
    if parsed.blocked_job_id:
        body_text += f"\nBlocked job: {parsed.blocked_job_id}"
    for uid in recipient_ids:
        push_notification(
            db,
            user_id=uid,
            type="warning",
            title=title,
            body=body_text,
            project_id=parsed.pid,
        )
    log_event(
        db,
        parsed.pid,
        getattr(request.state, "username", None),
        "scope",
        "extension_requested",
        f"Scope extension requested: {parsed.value.strip()} by {who}",
        {
            "value": parsed.value.strip(),
            "reason": parsed.reason.strip(),
            "job_id": parsed.blocked_job_id,
        },
    )
    db.commit()
    return {"ok": True, "notified": len(recipient_ids), "value": parsed.value.strip()}


@router.get("", response_model=list[schemas.Scope], responses={404: {"description": "Not found"}})
def list_scopes(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    pid: str | None = None,
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    if pid:
        check_pid_access(db, pid, user, "scopes.read")
        q = db.query(models.Scope).filter(models.Scope.pid == pid)
        total = q.count()
        response.headers["X-Total-Count"] = str(total)
        return q.offset(offset).limit(limit).all()
    if is_admin(user):
        q = db.query(models.Scope)
        total = q.count()
        response.headers["X-Total-Count"] = str(total)
        return q.offset(offset).limit(limit).all()
    member_pids = get_user_member_pids(db, user)
    q = db.query(models.Scope).filter(models.Scope.pid.in_(member_pids))
    total = q.count()
    response.headers["X-Total-Count"] = str(total)
    return q.offset(offset).limit(limit).all()


@router.post(
    "", response_model=schemas.Scope, status_code=201, responses={404: {"description": "Not found"}}
)
def create_scope(
    body: schemas.ScopeCreate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, body.pid, user, PERM_SCOPES_UPDATE)
    if body.is_entry:
        db.query(models.Scope).filter(
            models.Scope.pid == body.pid,
            models.Scope.is_entry,
        ).update({"is_entry": False})
    scope = models.Scope(**body.model_dump(), id=new_id("sc"))
    db.add(scope)
    sync_project_ip_from_scopes(db, scope.pid)
    log_event(
        db,
        scope.pid,
        getattr(request.state, "username", None),
        "scope",
        "create",
        f"Scope {'added' if scope.in_scope else 'excluded'}: {scope.value}",
        {"type": scope.scope_type},
    )
    db.commit()
    db.refresh(scope)
    bcast(scope.pid, "scope", "create", schemas.Scope.model_validate(scope).model_dump())
    return scope


@router.patch("/{sid}", response_model=schemas.Scope, responses={404: {"description": "Not found"}})
def update_scope(
    sid: str,
    body: schemas.ScopeUpdate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    scope = db.query(models.Scope).filter(models.Scope.id == sid).first()
    if not scope:
        raise HTTPException(404)
    check_object_access(db, scope.pid, user, PERM_SCOPES_UPDATE)
    if body.is_entry is True:
        db.query(models.Scope).filter(
            models.Scope.pid == scope.pid,
            models.Scope.id != sid,
            models.Scope.is_entry,
        ).update({"is_entry": False})
    for k, v in body.model_dump(exclude_none=True).items():
        setattr(scope, k, v)
    sync_project_ip_from_scopes(db, scope.pid)
    db.commit()
    db.refresh(scope)
    bcast(scope.pid, "scope", "update", schemas.Scope.model_validate(scope).model_dump())
    return scope


@router.delete("/{sid}", status_code=204, responses={404: {"description": "Not found"}})
def delete_scope(
    sid: str,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    scope = db.query(models.Scope).filter(models.Scope.id == sid).first()
    if not scope:
        raise HTTPException(404)
    check_object_access(db, scope.pid, user, PERM_SCOPES_UPDATE)
    pid = scope.pid
    log_event(
        db,
        pid,
        getattr(request.state, "username", None),
        "scope",
        "delete",
        f"Scope removed: {scope.value}",
    )
    db.delete(scope)
    sync_project_ip_from_scopes(db, pid)
    db.commit()
    bcast(pid, "scope", "delete", {"id": sid})
