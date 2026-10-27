"""Audit log query API."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import and_, desc, or_
from sqlalchemy.orm import Session

from .. import models
from ..core.deps import get_current_user, is_admin
from ..core.org_access import ORG_USER_MANAGER_ROLES
from ..database import get_db
from ..models.audit import AuditEntry

router = APIRouter(prefix="/api/audit", tags=["audit"])


@router.get("/log")
async def get_audit_log(
    pid: str | None = None,
    actor_id: str | None = None,
    action: str | None = None,
    target_type: str | None = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: models.User = Depends(get_current_user),
):
    """Query audit log. Platform admins see all; org owners/admins also see
    org-scoped entries (member/team add/remove/role_change — project_id is
    None on those, so the plain project_id-membership filter used to hide
    them from everyone but a platform_admin, 2026-08-18)."""
    q = db.query(AuditEntry)

    if not is_admin(user):
        member_pids = [
            m.project_id
            for m in db.query(models.ProjectMember)
            .filter(models.ProjectMember.user_id == user.id, models.ProjectMember.is_active)
            .all()
        ]
        # Same bar as who may add/remove org members in the first place
        # (org_access.ORG_USER_MANAGER_ROLES) — a manager/team_lead who can
        # act on their org's membership should be able to see the resulting
        # trail, not just owner/admin.
        admin_org_ids = [
            om.org_id
            for om in db.query(models.OrganizationMember).filter(
                models.OrganizationMember.user_id == user.id,
                models.OrganizationMember.role.in_(ORG_USER_MANAGER_ROLES),
            )
        ]
        org_scoped_target_types = ["org_member", "team_member", "org", "team"]
        conditions = [AuditEntry.project_id.in_(member_pids)] if member_pids else []
        if admin_org_ids:
            # Used to be a LIKE match against the detail JSON-text blob
            # (log_action() always wrote org_id into detail, never as a
            # queryable column) — replaced by the real org_id column added
            # for per-tier retention (ФТ-3, migration 096).
            conditions.append(
                and_(
                    AuditEntry.target_type.in_(org_scoped_target_types),
                    AuditEntry.org_id.in_(admin_org_ids),
                )
            )
        q = q.filter(or_(*conditions)) if conditions else q.filter(False)

    if pid:
        q = q.filter(AuditEntry.project_id == pid)
    if actor_id:
        q = q.filter(AuditEntry.actor_id == actor_id)
    if action:
        q = q.filter(AuditEntry.action == action)
    if target_type:
        q = q.filter(AuditEntry.target_type == target_type)

    total = q.count()
    entries = q.order_by(desc(AuditEntry.ts)).offset(offset).limit(limit).all()

    return {
        "total": total,
        "items": [
            {
                "id": e.id,
                "ts": e.ts.isoformat() if e.ts else None,
                "actor_id": e.actor_id,
                "actor_name": e.actor_name,
                "action": e.action,
                "target_type": e.target_type,
                "target_id": e.target_id,
                "project_id": e.project_id,
                "org_id": e.org_id,
                "detail": e.detail,
                "ip_address": e.ip_address,
            }
            for e in entries
        ],
    }
