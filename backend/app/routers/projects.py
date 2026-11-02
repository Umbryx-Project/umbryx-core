from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.access import check_pid_access, get_user_member_pids
from ..core.audit import ACT_PROJECT_CREATE, ACT_PROJECT_DELETE, ACT_PROJECT_UPDATE, log_action
from ..core.config import UPLOAD_ROOT
from ..core.deps import get_current_user, is_admin
from ..core.events import bcast, log_event
from ..core.permissions import add_project_owner, get_membership, get_permissions_for_role
from ..core.secure_delete import secure_delete_tree
from ..core.utils import new_id, sync_project_ip_from_scopes, sync_scopes_from_project_ip, ts_now
from ..database import get_db

router = APIRouter(
    prefix="/api/projects",
    tags=["projects"],
    responses={
        400: {"description": "Bad request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
        500: {"description": "Internal server error"},
    },
)

_MSG_PROJECT_NOT_FOUND = "Project not found"


class ProjectPurgeBody(BaseModel):
    confirm: str


@router.get("", response_model=list[schemas.Project])
def list_projects(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    if is_admin(user):
        return db.query(models.Project).all()
    member_pids = get_user_member_pids(db, user)
    if not member_pids:
        return []
    return db.query(models.Project).filter(models.Project.id.in_(member_pids)).all()


@router.post("", response_model=schemas.Project, status_code=201)
def create_project(
    body: schemas.ProjectCreate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    project = models.Project(id=new_id("p"), **body.model_dump())
    db.add(project)
    db.flush()
    sync_scopes_from_project_ip(db, project.id)
    add_project_owner(db, project.id, user.id, created_by=user.id)
    db.commit()
    db.refresh(project)
    log_event(
        db,
        project.id,
        user.username,
        "project",
        "create",
        f"Project created: {project.name}",
        {"project_id": project.id},
    )
    log_action(
        db,
        action=ACT_PROJECT_CREATE,
        actor_id=user.id,
        actor_name=user.username,
        target_type="project",
        target_id=project.id,
        project_id=project.id,
    )
    db.commit()
    return project


@router.patch(
    "/{pid}",
    response_model=schemas.Project,
    responses={403: {"description": "Forbidden"}, 404: {"description": "Not found"}},
)
def update_project(
    pid: str,
    body: schemas.ProjectUpdate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404, _MSG_PROJECT_NOT_FOUND)
    if not is_admin(user):
        membership = get_membership(db, pid, user.id)
        if not membership:
            raise HTTPException(404, _MSG_PROJECT_NOT_FOUND)
        if "project.update" not in get_permissions_for_role(membership.role):
            raise HTTPException(403, "Insufficient permissions")

    # Attaching/detaching a project to/from an org is what actually makes
    # the org's members see it (core/access.py::get_user_member_pids) — it
    # requires org-admin authority over the org on *both* ends of the
    # change (whoever currently owns the visibility being granted/revoked),
    # not just project.update, or any project editor could hand their
    # project's visibility to an org they don't administer.
    from ..core.org_access import require_org_admin

    if body.org_id is not None:
        require_org_admin(db, body.org_id, user)
        if project.org_id and project.org_id != body.org_id:
            require_org_admin(db, project.org_id, user)
        project.org_id = body.org_id
    elif body.detach_org and project.org_id:
        require_org_admin(db, project.org_id, user)
        project.org_id = None

    ip_changed = body.ip is not None
    for k, v in body.model_dump(exclude_none=True, exclude={"org_id", "detach_org"}).items():
        setattr(project, k, v)
    if ip_changed:
        sync_scopes_from_project_ip(db, pid)
        sync_project_ip_from_scopes(db, pid)
    db.commit()
    db.refresh(project)
    p = schemas.Project.model_validate(project)
    log_event(
        db,
        pid,
        user.username,
        "project",
        "update",
        f"Project updated: {project.name}",
        {"project_id": pid},
    )
    log_action(
        db,
        action=ACT_PROJECT_UPDATE,
        actor_id=user.id,
        actor_name=user.username,
        target_type="project",
        target_id=pid,
        project_id=pid,
    )
    db.commit()
    bcast(pid, "project", "update", p.model_dump())
    return project


@router.delete(
    "/{pid}",
    status_code=204,
    responses={403: {"description": "Forbidden"}, 404: {"description": "Not found"}},
)
def delete_project(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404, _MSG_PROJECT_NOT_FOUND)
    # Was a hand-rolled get_membership() check that bypassed the org-fallback
    # role resolution every other route in this router (and the rest of the
    # codebase) goes through via check_pid_access — an org-owner/org-admin
    # with no direct ProjectMember row got a misleading 404 "Project not
    # found" instead of a 403 reflecting their actual (still insufficient,
    # `admin` lacks project.delete — only `owner` has it) permission level.
    # Not a security hole (strictly more restrictive than intended), but
    # inconsistent with the permission matrix and a maintenance trap if that
    # matrix ever changes (RBAC retest, 2026-09-03).
    check_pid_access(db, pid, user, "project.delete")

    # Project-bound stacks outlive the project row: infra_stacks.project_id
    # has ondelete="SET NULL", so without this pass the stacks silently flip
    # to standalone while their cloud resources keep running (known gap in
    # ARCHITECTURE.md §2). Deliberately NOT destroyed here — teardown needs
    # provider access and an explicit decision; instead each stack is
    # stamped as orphaned so the Platform Ops "orphaned" filter surfaces it.
    orphaned_stacks = (
        db.query(models.InfraStack)
        .filter(
            models.InfraStack.project_id == pid,
            models.InfraStack.status.notin_(["destroyed", "tearing_down"]),
        )
        .all()
    )
    if orphaned_stacks:
        from ..core.devops_log import log_event
        from ..core.infra_orphans import notify_admins_orphaned_stack

        now = ts_now()
        for stack in orphaned_stacks:
            stack.project_id = None
            stack.mode = "standalone"
            stack.bound_at = None
            stack.bound_by = None
            stack.detached_at = now
            stack.detached_from_project = pid
            deployment_log = list(stack.deployment_log or [])
            deployment_log.append({"ts": now, "event": "orphaned_by_project_delete"})
            stack.deployment_log = deployment_log
            log_event(
                db,
                stack_id=stack.id,
                level="warn",
                category="lifecycle",
                message=(
                    f"Stack orphaned by project deletion: infrastructure "
                    f"was NOT destroyed and is still running (project {pid})"
                ),
                actor=user.id,
            )
            notify_admins_orphaned_stack(db, stack, source_pid=pid)
        db.flush()

    log_action(
        db,
        action=ACT_PROJECT_DELETE,
        actor_id=user.id,
        actor_name=user.username,
        target_type="project",
        target_id=pid,
        project_id=pid,
    )
    db.delete(project)
    db.commit()
    bcast(pid, "project", "delete", {"id": pid})


@router.post(
    "/{pid}/purge",
    responses={
        400: {"description": "Bad request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
        500: {"description": "Internal server error"},
    },
)
def purge_project(
    pid: str,
    body: ProjectPurgeBody,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404, _MSG_PROJECT_NOT_FOUND)
    if not is_admin(user):
        membership = get_membership(db, pid, user.id)
        if not membership:
            raise HTTPException(404, _MSG_PROJECT_NOT_FOUND)
        if "project.delete" not in get_permissions_for_role(membership.role):
            raise HTTPException(403, "Only project owners can purge projects")
    if body.confirm.strip() not in {pid, project.name, "PURGE"}:
        raise HTTPException(400, "Confirmation must match project id, project name, or PURGE")

    project_upload_dir = UPLOAD_ROOT / pid
    try:
        secure_delete_tree(project_upload_dir)
    except Exception as exc:
        raise HTTPException(500, f"Failed to remove project files: {exc}")

    db.query(models.TimelineEvent).filter(models.TimelineEvent.pid == pid).delete(
        synchronize_session=False
    )
    db.delete(project)
    db.commit()

    bcast(
        pid, "project", "purge", {"id": pid, "purged_by": getattr(request.state, "username", None)}
    )
    return {"ok": True, "purged": pid}


@router.get("/{pid}/my-role")
def my_project_role(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    if is_admin(user):
        return {"role": "owner", "project_id": pid}
    m = get_membership(db, pid, user.id)
    if not m:
        raise HTTPException(403, "Not a project member")
    return {"role": m.role, "project_id": pid}


@router.get("/meta/intensity-profiles")
def get_intensity_profiles(
    user: Annotated[models.User, Depends(get_current_user)],
):
    """Return available intensity profiles."""
    from ..core.intensity import INTENSITY_PROFILES

    return INTENSITY_PROFILES
