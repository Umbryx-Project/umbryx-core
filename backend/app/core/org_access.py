"""
Organization-level RBAC helpers, shared across routers.

Distinct from:
  - core/permissions.py — per-PROJECT roles (owner/admin/editor/...).
  - core/deps.py::require_admin — the single global `platform_admin` flag,
    which bypasses every project AND every organization boundary.

This is the middle tier: a person who administers one Organization
(its registries, its members) without holding the platform-wide flag.
Org roles reuse core/enums.py::MemberRole — same vocabulary as project
roles, but the two are unrelated memberships (OrganizationMember vs
ProjectMember).

"devops" is not a distinct role anywhere in the system — treat it as a
synonym for "admin" at the call site if it ever shows up in older data.
"""

from sqlalchemy.orm import Session

from .. import models
from .deps import is_admin
from .enums import MemberRole
from .errors import AppError

# Roles that may administer an org's own settings (registries, members,
# org profile) — same bar routers/organizations.py already uses for
# member add/remove/org update.
ORG_ADMIN_ROLES = {MemberRole.OWNER.value, MemberRole.ADMIN.value}

# Broader set that may create/onboard new users into the org — managers
# and team leads run their own people day-to-day but shouldn't need a
# platform_admin to hand-hold every new hire (2026-08-18).
ORG_USER_MANAGER_ROLES = ORG_ADMIN_ROLES | {MemberRole.MANAGER.value, MemberRole.TEAM_LEAD.value}

# Relative seniority for the "don't hand out more power than you have"
# check on org member/user creation — a team_lead granting someone the
# "admin" role would otherwise be a privilege escalation (caught by
# security review 2026-08-18: the original check only special-cased
# "owner", leaving every other role unchecked against the caller's own
# rank). Roles not listed here are all ordinary/non-privileged members —
# they share the lowest rank.
_ORG_ROLE_RANK = {
    MemberRole.OWNER.value: 6,
    MemberRole.ADMIN.value: 5,
    MemberRole.MANAGER.value: 4,
    MemberRole.TEAM_LEAD.value: 3,
}
_ORG_ROLE_RANK_DEFAULT = 1


def org_role_rank(role: str | None) -> int:
    if role is None:
        return 0
    return _ORG_ROLE_RANK.get(role, _ORG_ROLE_RANK_DEFAULT)


def caller_org_rank(db: Session, org_id: str, user: models.User) -> int:
    """platform_admin acts with owner-level rank for grant-ceiling
    purposes — they can already do anything via require_admin elsewhere,
    this just keeps the ceiling check from spuriously blocking them."""
    if is_admin(user):
        return _ORG_ROLE_RANK[MemberRole.OWNER.value]
    return org_role_rank(get_org_role(db, org_id, user.id))


def get_org_role(db: Session, org_id: str, user_id: str) -> str | None:
    m = (
        db.query(models.OrganizationMember)
        .filter(
            models.OrganizationMember.org_id == org_id,
            models.OrganizationMember.user_id == user_id,
        )
        .first()
    )
    return m.role if m else None


def is_org_admin(db: Session, org_id: str, user: models.User) -> bool:
    return is_admin(user) or get_org_role(db, org_id, user.id) in ORG_ADMIN_ROLES


def is_org_user_manager(db: Session, org_id: str, user: models.User) -> bool:
    return is_admin(user) or get_org_role(db, org_id, user.id) in ORG_USER_MANAGER_ROLES


def require_org_admin(db: Session, org_id: str, user: models.User) -> None:
    if not is_org_admin(db, org_id, user):
        raise AppError("org_admin_required", "Organization admin access required", status=403)


def require_org_user_manager(db: Session, org_id: str, user: models.User) -> None:
    if not is_org_user_manager(db, org_id, user):
        raise AppError(
            "org_admin_required",
            "Organization admin/manager access required",
            status=403,
        )
