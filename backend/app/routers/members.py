"""
Project members management API.
"""

import uuid
from datetime import UTC
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models
from ..core.access import _resolve_role, check_pid_access, user_has_permission
from ..core.audit import ACT_MEMBER_ADD, ACT_MEMBER_REMOVE, ACT_MEMBER_ROLE_CHANGE, log_action
from ..core.deps import get_current_user, is_admin
from ..core.enums import MemberRole
from ..core.events import log_event
from ..core.logging_setup import get_logger

logger = get_logger(__name__)
from ..core.permissions import (
    PROJECT_ROLES,
    add_project_owner,
    get_membership,
    get_permissions_for_role,
)
from ..core.plan import check_member_role_allowed
from ..core.utils import new_id, ts_now
from ..database import get_db

router = APIRouter(
    prefix="/api/projects",
    tags=["members"],
    responses={
        400: {"description": "Bad request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)

_MSG_PROJECT_NOT_FOUND = "Project not found"
_MSG_OWNER_ONLY = "Only owners can assign the owner role"


class MemberOut(BaseModel):
    user_id: str
    username: str
    role: str
    created_at: str
    created_by: str | None = None
    is_active: bool
    source: str = "direct"


class AddMemberBody(BaseModel):
    user_id: str
    role: str = "viewer"


class BulkAddMembersBody(BaseModel):
    user_ids: list[str]
    role: str = "viewer"


class UpdateRoleBody(BaseModel):
    role: str


class TransferOwnershipBody(BaseModel):
    user_id: str


class AvailableUserOut(BaseModel):
    id: str
    username: str
    role: str
    active: bool


def _get_project_or_404(pid: str, db: Session) -> models.Project:
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        raise HTTPException(404, _MSG_PROJECT_NOT_FOUND)
    return project


def _require_manage_members(pid: str, user: models.User, db: Session):
    if is_admin(user):
        return
    if not user_has_permission(db, pid, user, "project.manage_members"):
        raise HTTPException(403, "Insufficient permissions to manage members")


def _upsert_member(
    pid: str, user_id: str, role: str, actor_id: str, db: Session
) -> models.ProjectMember:
    existing = (
        db.query(models.ProjectMember)
        .filter(
            models.ProjectMember.project_id == pid,
            models.ProjectMember.user_id == user_id,
        )
        .first()
    )
    if existing:
        existing.role = role
        existing.is_active = True
        existing.created_by = actor_id
        return existing

    member = models.ProjectMember(
        id=new_id("pm"),
        project_id=pid,
        user_id=user_id,
        role=role,
        source="direct",
        created_at=ts_now(),
        created_by=actor_id,
        is_active=True,
    )
    db.add(member)
    return member


@router.get(
    "/{pid}/members",
    response_model=list[MemberOut],
    responses={
        400: {"description": "Bad request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)
def list_members(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _get_project_or_404(pid, db)
    if not is_admin(user):
        check_pid_access(db, pid, user)

    seen: dict[str, MemberOut] = {}

    for m, u in (
        db.query(models.ProjectMember, models.User)
        .join(models.User, models.ProjectMember.user_id == models.User.id)
        .filter(models.ProjectMember.project_id == pid, models.ProjectMember.is_active)
        .all()
    ):
        seen[m.user_id] = MemberOut(
            user_id=m.user_id,
            username=u.username,
            role=m.role,
            created_at=m.created_at,
            created_by=m.created_by,
            is_active=m.is_active,
            source="direct",
        )

    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if project and project.org_id:
        team_ids = [
            pt.team_id
            for pt in db.query(models.ProjectTeam)
            .filter(models.ProjectTeam.project_id == pid)
            .all()
        ]
        if team_ids:
            for tm, u in (
                db.query(models.TeamMember, models.User)
                .join(models.User, models.TeamMember.user_id == models.User.id)
                .filter(models.TeamMember.team_id.in_(team_ids))
                .all()
            ):
                if tm.user_id not in seen:
                    role = tm.default_project_role or tm.role or MemberRole.VIEWER.value
                    seen[tm.user_id] = MemberOut(
                        user_id=tm.user_id,
                        username=u.username,
                        role=role,
                        created_at=tm.created_at,
                        created_by=None,
                        is_active=True,
                        source="team",
                    )

        for om, u in (
            db.query(models.OrganizationMember, models.User)
            .join(models.User, models.OrganizationMember.user_id == models.User.id)
            .filter(
                models.OrganizationMember.org_id == project.org_id,
                models.OrganizationMember.role.in_(
                    [MemberRole.OWNER.value, MemberRole.ADMIN.value]
                ),
            )
            .all()
        ):
            if om.user_id not in seen:
                seen[om.user_id] = MemberOut(
                    user_id=om.user_id,
                    username=u.username,
                    role=MemberRole.ADMIN.value,
                    created_at=om.created_at,
                    created_by=None,
                    is_active=True,
                    source="org_admin",
                )

    return list(seen.values())


@router.post(
    "/{pid}/members",
    status_code=201,
    response_model=MemberOut,
    responses={
        400: {"description": "Bad request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)
def add_member(
    pid: str,
    body: AddMemberBody,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _get_project_or_404(pid, db)
    _require_manage_members(pid, user, db)

    if body.role not in PROJECT_ROLES:
        raise HTTPException(400, f"Invalid role. Valid roles: {PROJECT_ROLES}")
    check_member_role_allowed(body.role, db)

    if body.role == MemberRole.OWNER and not is_admin(user):
        caller_membership = get_membership(db, pid, user.id)
        if not caller_membership or caller_membership.role != "owner":
            raise HTTPException(403, _MSG_OWNER_ONLY)

    target_user = (
        db.query(models.User).filter(models.User.id == body.user_id, models.User.active).first()
    )
    if not target_user:
        raise HTTPException(404, "User not found")

    member = _upsert_member(pid, body.user_id, body.role, user.id, db)
    log_event(
        db,
        pid,
        user.username,
        "member",
        "add",
        f"Member added: {target_user.username} ({body.role})",
        {"user_id": body.user_id, "role": body.role},
    )
    log_action(
        db,
        action=ACT_MEMBER_ADD,
        actor_id=user.id,
        actor_name=user.username,
        target_type="member",
        target_id=body.user_id,
        project_id=pid,
        detail={"role": body.role, "username": target_user.username},
    )
    try:
        from ..core.instance_manager import sync_project_users

        sync_project_users(db, pid)
    except Exception as exc:
        # Audit 2026-08-31, 2.3.5: a desynced external-user/group mapping was
        # silently invisible — log who/what failed instead of swallowing.
        logger.warning(
            "member add: sync_project_users failed for project %s (new member %s): %s",
            pid,
            body.user_id,
            exc,
        )
    try:
        from ..core.notify import push_notification

        push_notification(
            db,
            user_id=body.user_id,
            type="info",
            title="Added to project",
            body="You were added to a project",
            project_id=pid,
        )
    except Exception as exc:
        logger.warning(
            "member add: welcome notification failed for user %s in project %s: %s",
            body.user_id,
            pid,
            exc,
        )
    db.commit()
    db.refresh(member)
    return MemberOut(
        user_id=member.user_id,
        username=target_user.username,
        role=member.role,
        created_at=member.created_at,
        created_by=member.created_by,
        is_active=member.is_active,
    )


@router.post(
    "/{pid}/members/bulk",
    status_code=201,
    response_model=list[MemberOut],
    responses={
        400: {"description": "Bad request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)
def bulk_add_members(
    pid: str,
    body: BulkAddMembersBody,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _get_project_or_404(pid, db)
    _require_manage_members(pid, user, db)

    if body.role not in PROJECT_ROLES:
        raise HTTPException(400, f"Invalid role. Valid roles: {PROJECT_ROLES}")
    check_member_role_allowed(body.role, db)
    if not body.user_ids:
        raise HTTPException(400, "No users provided")
    if body.role == MemberRole.OWNER and not is_admin(user):
        caller_membership = get_membership(db, pid, user.id)
        if not caller_membership or caller_membership.role != "owner":
            raise HTTPException(403, _MSG_OWNER_ONLY)

    user_ids = list(dict.fromkeys(uid for uid in body.user_ids if uid))
    target_users = (
        db.query(models.User).filter(models.User.id.in_(user_ids), models.User.active).all()
    )
    target_map = {u.id: u for u in target_users}
    missing_ids = [uid for uid in user_ids if uid not in target_map]
    if missing_ids:
        raise HTTPException(404, f"Users not found: {', '.join(missing_ids[:5])}")

    members = []
    for uid in user_ids:
        member = _upsert_member(pid, uid, body.role, user.id, db)
        members.append(member)

    db.commit()
    for member in members:
        db.refresh(member)

    return [
        MemberOut(
            user_id=member.user_id,
            username=target_map[member.user_id].username,
            role=member.role,
            created_at=member.created_at,
            created_by=member.created_by,
            is_active=member.is_active,
        )
        for member in members
    ]


@router.get(
    "/{pid}/available-users",
    response_model=list[AvailableUserOut],
    responses={
        400: {"description": "Bad request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)
def list_available_users(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _get_project_or_404(pid, db)
    _require_manage_members(pid, user, db)

    exclude_ids: set[str] = set()

    for (uid,) in (
        db.query(models.ProjectMember.user_id)
        .filter(
            models.ProjectMember.project_id == pid,
            models.ProjectMember.is_active,
        )
        .all()
    ):
        exclude_ids.add(uid)

    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if project and project.org_id:
        team_ids = [
            pt.team_id
            for pt in db.query(models.ProjectTeam)
            .filter(models.ProjectTeam.project_id == pid)
            .all()
        ]
        if team_ids:
            for (uid,) in (
                db.query(models.TeamMember.user_id)
                .filter(models.TeamMember.team_id.in_(team_ids))
                .all()
            ):
                exclude_ids.add(uid)

        for (uid,) in (
            db.query(models.OrganizationMember.user_id)
            .filter(
                models.OrganizationMember.org_id == project.org_id,
                models.OrganizationMember.role.in_(
                    [MemberRole.OWNER.value, MemberRole.ADMIN.value]
                ),
            )
            .all()
        ):
            exclude_ids.add(uid)

    query = db.query(models.User).filter(models.User.active)
    if exclude_ids:
        query = query.filter(~models.User.id.in_(exclude_ids))

    users = query.order_by(models.User.username).all()
    return [
        AvailableUserOut(id=u.id, username=u.username, role=u.role, active=u.active) for u in users
    ]


@router.patch(
    "/{pid}/members/{target_uid}",
    response_model=MemberOut,
    responses={
        400: {"description": "Bad request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)
def update_member_role(
    pid: str,
    target_uid: str,
    body: UpdateRoleBody,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _get_project_or_404(pid, db)
    _require_manage_members(pid, user, db)

    if body.role not in PROJECT_ROLES:
        raise HTTPException(400, f"Invalid role. Valid roles: {PROJECT_ROLES}")
    check_member_role_allowed(body.role, db)

    target_membership = (
        db.query(models.ProjectMember)
        .filter(
            models.ProjectMember.project_id == pid,
            models.ProjectMember.user_id == target_uid,
            models.ProjectMember.is_active,
        )
        .first()
    )
    if not target_membership:
        raise HTTPException(404, "Member not found")

    target_user = db.query(models.User).filter(models.User.id == target_uid).first()

    if target_membership.role == MemberRole.OWNER and not is_admin(user):
        caller_membership = get_membership(db, pid, user.id)
        if not caller_membership or caller_membership.role != "owner":
            raise HTTPException(403, "Cannot change role of project owner")

    if body.role == MemberRole.OWNER and not is_admin(user):
        caller_membership = get_membership(db, pid, user.id)
        if not caller_membership or caller_membership.role != "owner":
            raise HTTPException(403, _MSG_OWNER_ONLY)

    old_role = target_membership.role
    target_membership.role = body.role
    log_event(
        db,
        pid,
        user.username,
        "member",
        "role_change",
        f"Role changed: {target_user.username if target_user else target_uid} {old_role} → {body.role}",
        {"user_id": target_uid, "old_role": old_role, "new_role": body.role},
    )
    log_action(
        db,
        action=ACT_MEMBER_ROLE_CHANGE,
        actor_id=user.id,
        actor_name=user.username,
        target_type="member",
        target_id=target_uid,
        project_id=pid,
        detail={"old_role": old_role, "new_role": body.role},
    )
    db.commit()
    db.refresh(target_membership)
    return MemberOut(
        user_id=target_membership.user_id,
        username=target_user.username if target_user else target_uid,
        role=target_membership.role,
        created_at=target_membership.created_at,
        created_by=target_membership.created_by,
        is_active=target_membership.is_active,
    )


@router.delete(
    "/{pid}/members/{target_uid}",
    status_code=204,
    responses={
        400: {"description": "Bad request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)
def remove_member(
    pid: str,
    target_uid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _get_project_or_404(pid, db)
    _require_manage_members(pid, user, db)

    target_membership = (
        db.query(models.ProjectMember)
        .filter(
            models.ProjectMember.project_id == pid,
            models.ProjectMember.user_id == target_uid,
            models.ProjectMember.is_active,
        )
        .first()
    )
    if not target_membership:
        raise HTTPException(404, "Member not found")

    if target_membership.role == MemberRole.OWNER and not is_admin(user):
        caller_membership = get_membership(db, pid, user.id)
        if not caller_membership or caller_membership.role != "owner":
            raise HTTPException(403, "Cannot remove project owner")

    if target_membership.role == MemberRole.OWNER:
        owner_count = (
            db.query(models.ProjectMember)
            .filter(
                models.ProjectMember.project_id == pid,
                models.ProjectMember.role == MemberRole.OWNER,
                models.ProjectMember.is_active,
            )
            .count()
        )
        if owner_count <= 1:
            raise HTTPException(400, "Cannot remove the last owner of a project")

    target_membership.is_active = False
    log_event(
        db,
        pid,
        user.username,
        "member",
        "remove",
        f"Member removed: {target_uid} ({target_membership.role})",
        {"user_id": target_uid, "role": target_membership.role},
    )
    log_action(
        db,
        action=ACT_MEMBER_REMOVE,
        actor_id=user.id,
        actor_name=user.username,
        target_type="member",
        target_id=target_uid,
        project_id=pid,
        detail={"role": target_membership.role},
    )
    try:
        from ..core.instance_manager import sync_project_users

        sync_project_users(db, pid)
    except Exception as exc:
        # Audit 2026-08-31, 2.3.5: keep the desync visible instead of a
        # silent pass after member removal.
        logger.warning(
            "member remove: sync_project_users failed for project %s (removed %s): %s",
            pid,
            target_uid,
            exc,
        )
    db.commit()


@router.post(
    "/{pid}/transfer-ownership",
    status_code=200,
    responses={
        400: {"description": "Bad request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)
def transfer_ownership(
    pid: str,
    body: TransferOwnershipBody,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _get_project_or_404(pid, db)

    if not is_admin(user):
        caller_membership = get_membership(db, pid, user.id)
        if not caller_membership or caller_membership.role != "owner":
            raise HTTPException(403, "Only project owner can transfer ownership")

    target_user = (
        db.query(models.User).filter(models.User.id == body.user_id, models.User.active).first()
    )
    if not target_user:
        raise HTTPException(404, "Target user not found")

    add_project_owner(db, pid, body.user_id, created_by=user.id)

    if not is_admin(user):
        caller_membership = get_membership(db, pid, user.id)
        if caller_membership and caller_membership.user_id != body.user_id:
            caller_membership.role = MemberRole.ADMIN

    db.commit()
    return {"message": "Ownership transferred successfully"}


@router.get(
    "/{pid}/permissions/me",
    responses={
        400: {"description": "Bad request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)
def get_my_permissions(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _get_project_or_404(pid, db)

    if is_admin(user):
        from ..core.permissions import ROLE_PERMISSIONS

        all_perms = set()
        for perms in ROLE_PERMISSIONS.values():
            all_perms |= perms
        return {
            "project_id": pid,
            "role": "super_admin",
            "permissions": sorted(all_perms),
            "is_super_admin": True,
        }

    role, source = _resolve_role(db, pid, user)
    if role is None:
        raise HTTPException(404, _MSG_PROJECT_NOT_FOUND)

    return {
        "project_id": pid,
        "role": role,
        "permissions": sorted(get_permissions_for_role(role)),
        "is_super_admin": False,
        "source": source,
    }


# ── Invitations ──────────────────────────────────────────────────────


class InviteCreateBody(BaseModel):
    role: str = "viewer"
    expires_hours: int = 72


class InviteOut(BaseModel):
    id: str
    project_id: str
    token: str
    role: str
    invited_by: str
    created_at: str
    expires_at: str | None
    accepted_at: str | None
    accepted_by: str | None
    revoked: bool


class AcceptInviteBody(BaseModel):
    token: str


@router.post("/{pid}/invitations", status_code=201, response_model=InviteOut)
def create_invitation(
    pid: str,
    body: InviteCreateBody,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _get_project_or_404(pid, db)
    _require_manage_members(pid, user, db)

    if body.role not in PROJECT_ROLES:
        raise HTTPException(400, f"Invalid role. Valid roles: {PROJECT_ROLES}")
    check_member_role_allowed(body.role, db)

    if body.role == MemberRole.OWNER and not is_admin(user):
        caller_membership = get_membership(db, pid, user.id)
        if not caller_membership or caller_membership.role != "owner":
            raise HTTPException(403, _MSG_OWNER_ONLY)

    from datetime import datetime, timedelta

    now = datetime.now(UTC)
    expires_at = (now + timedelta(hours=body.expires_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")

    inv = models.ProjectInvitation(
        id=new_id("inv"),
        project_id=pid,
        token=uuid.uuid4().hex,
        role=body.role,
        invited_by=user.id,
        created_at=ts_now(),
        expires_at=expires_at,
    )
    db.add(inv)
    db.commit()
    db.refresh(inv)
    return inv


@router.get("/{pid}/invitations", response_model=list[InviteOut])
def list_invitations(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _get_project_or_404(pid, db)
    _require_manage_members(pid, user, db)
    return (
        db.query(models.ProjectInvitation)
        .filter(
            models.ProjectInvitation.project_id == pid,
            ~models.ProjectInvitation.revoked,
            models.ProjectInvitation.accepted_at.is_(None),
        )
        .order_by(models.ProjectInvitation.created_at.desc())
        .all()
    )


@router.post("/{pid}/invitations/{inv_id}/revoke", status_code=200)
def revoke_invitation(
    pid: str,
    inv_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _get_project_or_404(pid, db)
    _require_manage_members(pid, user, db)
    inv = (
        db.query(models.ProjectInvitation)
        .filter(
            models.ProjectInvitation.id == inv_id,
            models.ProjectInvitation.project_id == pid,
        )
        .first()
    )
    if not inv:
        raise HTTPException(404, "Invitation not found")
    inv.revoked = True
    db.commit()
    return {"message": "Invitation revoked"}


@router.post("/accept-invite", status_code=200)
def accept_invitation(
    body: AcceptInviteBody,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    inv = (
        db.query(models.ProjectInvitation)
        .filter(
            models.ProjectInvitation.token == body.token,
            ~models.ProjectInvitation.revoked,
            models.ProjectInvitation.accepted_at.is_(None),
        )
        .first()
    )
    if not inv:
        raise HTTPException(404, "Invitation not found or already used")

    if inv.expires_at:
        from datetime import datetime

        now = datetime.now(UTC)
        try:
            exp = datetime.fromisoformat(inv.expires_at.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            raise HTTPException(400, "Invitation has invalid expiry format")
        if now > exp:
            raise HTTPException(410, "Invitation has expired")

    existing = (
        db.query(models.ProjectMember)
        .filter(
            models.ProjectMember.project_id == inv.project_id,
            models.ProjectMember.user_id == user.id,
        )
        .first()
    )
    if existing and existing.is_active:
        raise HTTPException(409, "Already a member of this project")

    if existing:
        existing.role = inv.role
        existing.is_active = True
    else:
        member = models.ProjectMember(
            id=new_id("pm"),
            project_id=inv.project_id,
            user_id=user.id,
            role=inv.role,
            source="direct",
            created_at=ts_now(),
            created_by=inv.invited_by,
            is_active=True,
        )
        db.add(member)

    inv.accepted_at = ts_now()
    inv.accepted_by = user.id
    log_event(
        db,
        inv.project_id,
        user.username,
        "member",
        "invite_accept",
        f"Joined via invitation ({inv.role})",
        {"role": inv.role, "invited_by": inv.invited_by},
    )
    db.commit()
    return {"project_id": inv.project_id, "role": inv.role}


# ── Team attachment ───────────────────────────────────────────────────


class AttachTeamBody(BaseModel):
    team_id: str


@router.post("/{pid}/teams", status_code=201)
def attach_team(
    pid: str,
    body: AttachTeamBody,
    user: Annotated[models.User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    if not is_admin(user) and not user_has_permission(db, pid, user, "project.manage_members"):
        raise HTTPException(403, "Insufficient permissions")

    project = _get_project_or_404(pid, db)
    team = db.query(models.Team).filter(models.Team.id == body.team_id).first()
    if not team:
        raise HTTPException(404, "Team not found")

    if not project.org_id or team.org_id != project.org_id:
        raise HTTPException(400, "Team must belong to the same organization as the project")

    existing = (
        db.query(models.ProjectTeam)
        .filter(
            models.ProjectTeam.project_id == pid,
            models.ProjectTeam.team_id == body.team_id,
        )
        .first()
    )
    if existing:
        raise HTTPException(409, "Team already attached")

    pt = models.ProjectTeam(
        id=new_id("pt"),
        project_id=pid,
        team_id=body.team_id,
        attached_at=ts_now(),
        attached_by=user.id,
    )
    db.add(pt)

    team_member_count = (
        db.query(models.TeamMember).filter(models.TeamMember.team_id == body.team_id).count()
    )

    log_event(
        db,
        pid,
        user.username,
        "member",
        "team_attach",
        f"Attached team '{team.name}' ({team_member_count} members)",
        {"team_id": body.team_id, "members": team_member_count},
    )
    db.commit()
    return {"project_id": pid, "team_id": body.team_id, "members_count": team_member_count}


@router.delete("/{pid}/teams/{team_id}", status_code=204)
def detach_team(
    pid: str,
    team_id: str,
    user: Annotated[models.User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    if not is_admin(user) and not user_has_permission(db, pid, user, "project.manage_members"):
        raise HTTPException(403, "Insufficient permissions")

    pt = (
        db.query(models.ProjectTeam)
        .filter(
            models.ProjectTeam.project_id == pid,
            models.ProjectTeam.team_id == team_id,
        )
        .first()
    )
    if not pt:
        raise HTTPException(404, "Team not attached to this project")

    db.delete(pt)
    team = db.query(models.Team).filter(models.Team.id == team_id).first()
    team_name = team.name if team else team_id
    log_event(
        db,
        pid,
        user.username,
        "member",
        "team_detach",
        f"Detached team '{team_name}'",
        {"team_id": team_id},
    )
    db.commit()
    return None


@router.get("/{pid}/teams")
def list_project_teams(
    pid: str,
    user: Annotated[models.User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    check_pid_access(db, pid, user, None)
    pts = db.query(models.ProjectTeam).filter(models.ProjectTeam.project_id == pid).all()
    result = []
    for pt in pts:
        team = db.query(models.Team).filter(models.Team.id == pt.team_id).first()
        tm_count = (
            db.query(models.TeamMember)
            .filter(
                models.TeamMember.team_id == pt.team_id,
            )
            .count()
        )
        result.append(
            {
                "team_id": pt.team_id,
                "team_name": team.name if team else pt.team_id,
                "attached_at": pt.attached_at,
                "attached_by": pt.attached_by,
                "member_count": tm_count,
            }
        )
    return result
