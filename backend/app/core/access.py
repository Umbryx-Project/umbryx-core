from __future__ import annotations

import logging

from fastapi import HTTPException
from sqlalchemy.orm import Session

from .. import models
from .deps import is_admin
from .enums import MemberRole
from .permissions import get_membership, get_permissions_for_role

logger = logging.getLogger(__name__)

_ROLE_HIERARCHY = [
    MemberRole.OWNER.value,
    MemberRole.ADMIN.value,
    MemberRole.EDITOR.value,
    MemberRole.MANAGER.value,
    MemberRole.TEAM_LEAD.value,
    MemberRole.OPERATOR.value,
    MemberRole.ANALYST.value,
    MemberRole.REVIEWER.value,
    MemberRole.VIEWER.value,
    MemberRole.OBSERVER.value,
    MemberRole.AUDITOR.value,
]


def _role_rank(role: str) -> int:
    try:
        return _ROLE_HIERARCHY.index(role)
    except ValueError:
        return len(_ROLE_HIERARCHY)


def _get_project(db: Session, pid: str) -> models.Project | None:
    return db.query(models.Project).filter(models.Project.id == pid).first()


def _resolve_role(db: Session, pid: str, user: models.User) -> tuple[str | None, str]:
    membership = get_membership(db, pid, user.id)
    if membership and membership.is_active:
        return membership.role, "direct"

    project = _get_project(db, pid)
    if not project or not project.org_id:
        return None, "none"

    org_member = (
        db.query(models.OrganizationMember)
        .filter(
            models.OrganizationMember.org_id == project.org_id,
            models.OrganizationMember.user_id == user.id,
        )
        .first()
    )
    if not org_member:
        return None, "none"

    if org_member.role in (MemberRole.OWNER.value, MemberRole.ADMIN.value):
        from .logging_setup import get_logger

        get_logger(__name__).info(
            "ORG_ADMIN_BYPASS user=%s project=%s org=%s role=%s",
            user.id,
            pid,
            project.org_id,
            org_member.role,
        )
        return MemberRole.ADMIN.value, "org_admin"

    # Security audit 2026-10-07 (M6): an explicit INACTIVE ProjectMember row
    # is a deliberate removal from this project — it used to fall through to
    # the org-member/team fallbacks below, so removing someone from a project
    # never actually revoked their access while they stayed in the org.
    # Org owner/admin (handled above) keeps its documented org-wide reach.
    if membership is not None and not membership.is_active:
        return None, "revoked"

    team_ids = [
        pt.team_id
        for pt in db.query(models.ProjectTeam).filter(models.ProjectTeam.project_id == pid).all()
    ]
    best_role = None
    if team_ids:
        for tm in (
            db.query(models.TeamMember)
            .filter(
                models.TeamMember.team_id.in_(team_ids),
                models.TeamMember.user_id == user.id,
            )
            .all()
        ):
            role = tm.default_project_role or tm.role or MemberRole.VIEWER.value
            if best_role is None or _role_rank(role) < _role_rank(best_role):
                best_role = role
    if best_role:
        return best_role, "team"

    # Every remaining org member (manager/team_lead/analyst/... — anything
    # short of owner/admin, already handled above) gets default visibility
    # into all of their org's projects, at a permission level matching
    # their org role 1:1 (org roles reuse the exact same MemberRole
    # vocabulary as project roles). Previously only org owner/admin had
    # this fallback, so every other org role needed a manual per-project
    # ProjectMember row added through the admin panel before they could
    # even see a project belonging to their own org (2026-08-18).
    if MemberRole.coerce(org_member.role) is not None:
        return org_member.role, "org_member"

    return None, "none"


def _evaluate(
    db: Session,
    pid: str,
    user: models.User,
    permission: str | None,
) -> tuple[models.ProjectMember | None, str | None]:
    if is_admin(user):
        return None, None

    role, source = _resolve_role(db, pid, user)
    if role is None:
        return None, "not_member"

    if permission and permission not in get_permissions_for_role(role):
        membership = get_membership(db, pid, user.id)
        return membership, "no_permission"

    return get_membership(db, pid, user.id), None


def _audit_admin_bypass(db: Session, pid: str, user: models.User, permission: str | None) -> None:
    from .events import log_event

    # Captured up front, not re-read from `user` inside the except block: a
    # failed flush/commit below invalidates every object the session has
    # loaded, and touching an attribute on one of them afterwards (even a
    # plain string PK) forces SQLAlchemy to re-query — which raises
    # PendingRollbackError before `db.rollback()` on the next line ever
    # runs, turning this "best-effort, never raise" logger call into the
    # actual unhandled exception (found live against Postgres — SQLite,
    # used by the test suite, doesn't enforce the FK involved, so this
    # never reproduced under pytest; security retest, 2026-09-03).
    user_id = user.id
    username = user.username
    try:
        log_event(
            db,
            pid,
            username,
            "audit",
            "admin_bypass_access",
            f"Platform admin '{username}' accessed project without membership",
            {"permission": permission, "user_id": user_id},
        )
        db.commit()
    except Exception as exc:
        try:
            db.rollback()
        except Exception:
            pass
        logger.warning("admin_bypass audit write failed for pid=%s user=%s: %s", pid, user_id, exc)


def check_pid_access(
    db: Session,
    pid: str,
    user: models.User,
    permission: str | None = None,
) -> models.ProjectMember | None:
    membership, err = _evaluate(db, pid, user, permission)
    if err == "not_member":
        from .errors import AppError

        raise AppError("not_member", "Not found", status=404)
    if err == "no_permission":
        from .errors import AppError

        raise AppError(
            "insufficient_permissions",
            "Insufficient permissions",
            status=403,
            details={"required": permission} if permission else None,
        )
    # Only worth auditing — and, on Postgres, only possible to write at all
    # — when `pid` names a real project: timeline_events.pid carries a real
    # FK to projects.id, so a bypass "record" for a nonexistent project
    # can't be inserted; _get_project() here is what stopped that INSERT
    # from being attempted (and failing) in the first place.
    if (
        is_admin(user)
        and permission
        and get_membership(db, pid, user.id) is None
        and _get_project(db, pid) is not None
    ):
        _audit_admin_bypass(db, pid, user, permission)
    return membership


def check_object_access(
    db: Session,
    pid: str | None,
    user: models.User,
    permission: str | None = None,
) -> models.ProjectMember | None:
    if not pid:
        from .errors import AppError

        raise AppError("not_found", "Not found", status=404)
    return check_pid_access(db, pid, user, permission)


def require_attack_path_in_project(db: Session, path_id: str, pid: str) -> models.AttackPath:
    """The attack path *path_id*, or 404 unless it belongs to *pid*.

    Permission on an attack path's children is checked against the ``pid`` in
    the request body, but the body also names the ``path_id`` to attach to, and
    nothing used to tie the two together: a user with a project of their own
    could post a node, edge, branch or step into ANY project's attack path by
    sending their own pid with a foreign path_id. The write landed and the
    victim project's members saw it (reads were never affected — those resolve
    the project from the path).

    404 rather than 403, matching how reads answer for a project the caller is
    not a member of: whether that path id exists is not something to confirm.
    """
    path = db.query(models.AttackPath).filter(models.AttackPath.id == path_id).first()
    if not path or path.pid != pid:
        raise HTTPException(404, "Attack path not found")
    return path


def user_has_permission(db: Session, pid: str, user: models.User, permission: str) -> bool:
    _, err = _evaluate(db, pid, user, permission)
    return err is None


def get_user_member_pids(db: Session, user: models.User) -> list[str]:
    pids = set()

    if is_admin(user):
        return [p.id for p in db.query(models.Project).all()]

    for m in (
        db.query(models.ProjectMember)
        .filter(
            models.ProjectMember.user_id == user.id,
            models.ProjectMember.is_active,
        )
        .all()
    ):
        pids.add(m.project_id)

    # Any org membership (any role) grants default visibility into that
    # org's projects — see the matching fallback in _resolve_role() above,
    # which is what determines the actual effective permission level once
    # the project is visible here.
    org_ids = [
        om.org_id
        for om in db.query(models.OrganizationMember)
        .filter(models.OrganizationMember.user_id == user.id)
        .all()
    ]
    if org_ids:
        for p in db.query(models.Project).filter(models.Project.org_id.in_(org_ids)).all():
            pids.add(p.id)

    team_ids = [
        tm.team_id
        for tm in db.query(models.TeamMember).filter(models.TeamMember.user_id == user.id).all()
    ]
    if team_ids:
        for pt in (
            db.query(models.ProjectTeam).filter(models.ProjectTeam.team_id.in_(team_ids)).all()
        ):
            pids.add(pt.project_id)

    return list(pids)


def resolve_user_role(db: Session, pid: str, user: models.User) -> str:
    if is_admin(user):
        return "platform_admin"
    role, _ = _resolve_role(db, pid, user)
    return role or ""


def resolve_user_source(db: Session, pid: str, user: models.User) -> str:
    if is_admin(user):
        return "platform_admin"
    _, source = _resolve_role(db, pid, user)
    return source
