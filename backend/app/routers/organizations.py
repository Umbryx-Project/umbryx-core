"""
Organization & Team management API.
"""

import re
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models
from ..core.audit import ACT_MEMBER_ADD, ACT_MEMBER_REMOVE, ACT_MEMBER_ROLE_CHANGE, log_action
from ..core.deps import get_current_user, is_admin
from ..core.enums import MemberRole, UserRole
from ..core.events import bcast
from ..core.org_access import caller_org_rank, org_role_rank, require_org_user_manager
from ..core.plan import check_member_role_allowed
from ..core.security import hash_password, validate_password_strength
from ..core.utils import new_id, ts_now
from ..database import get_db


def _bcast_org_member(org_id: str, action: str, data: dict) -> None:
    """Realtime fan-out for the org member list — room key `org:<id>` rides
    the same ConnectionManager/broadcast() every project room uses (see
    `/ws/{pid}` in main.py accepting that prefix), not a separate
    mechanism. Every subscriber's own action is echoed back to them too
    (there's no WS handle to exclude from a plain REST endpoint) — the
    frontend merge is written to be idempotent so that's harmless
    (2026-08-18: member add/remove/role-change required a manual page
    reload to show up for anyone, including the actor)."""
    bcast(f"org:{org_id}", "org_member", action, data)


router = APIRouter(
    prefix="/api/orgs",
    tags=["organizations"],
    responses={
        400: {"description": "Bad request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,48}[a-z0-9]$")


class OrgCreate(BaseModel):
    name: str
    slug: str


class OrgUpdate(BaseModel):
    name: str | None = None
    slug: str | None = None


class OrgOut(BaseModel):
    # No "plan"/tier field here on purpose (ФТ-11, docs/modules/
    # LICENSING_TZ.md): Organization.plan used to be a free-text column any
    # org owner could set via this same API and that nothing in
    # enforcement ever read — real entitlement lives in OrganizationPlan,
    # see GET /api/marketplace/plans/{org_id} or
    # GET /api/orgs/{org_id}/license/status.
    id: str
    name: str
    slug: str
    created_at: str
    # Caller's own role in this org — None only for a platform_admin who
    # isn't an actual member (they still see/manage every org via the
    # global bypass). This is the source of truth the frontend uses for
    # "does this user administer this org" — previously the org-admin
    # menu was gated on the currently-selected *project's* role, which is
    # an unrelated axis (2026-08-18).
    role: str | None = None


class OrgMemberAdd(BaseModel):
    user_id: str | None = None
    username: str | None = None
    role: str = "viewer"


class OrgUserCreate(BaseModel):
    username: str
    password: str
    display_name: str | None = None
    role: str = "viewer"


class OrgMemberOut(BaseModel):
    user_id: str
    username: str
    role: str
    created_at: str


class TeamCreate(BaseModel):
    name: str


class TeamOut(BaseModel):
    id: str
    org_id: str
    name: str
    created_at: str


class TeamMemberAdd(BaseModel):
    user_id: str | None = None
    username: str | None = None
    role: str = "viewer"
    default_project_role: str = "viewer"


class TeamMemberOut(BaseModel):
    user_id: str
    username: str
    role: str
    default_project_role: str = "viewer"
    created_at: str


def _require_org_admin(org_id: str, user: models.User, db: Session):
    if is_admin(user):
        return
    m = (
        db.query(models.OrganizationMember)
        .filter(
            models.OrganizationMember.org_id == org_id,
            models.OrganizationMember.user_id == user.id,
            models.OrganizationMember.role.in_([MemberRole.OWNER, MemberRole.ADMIN]),
        )
        .first()
    )
    if not m:
        raise HTTPException(403, "Organization admin access required")


def _require_org_member(org_id: str, user: models.User, db: Session):
    if is_admin(user):
        return
    m = (
        db.query(models.OrganizationMember)
        .filter(
            models.OrganizationMember.org_id == org_id,
            models.OrganizationMember.user_id == user.id,
        )
        .first()
    )
    if not m:
        raise HTTPException(403, "Not an organization member")


# ── Organization CRUD ────────────────────────────────────────────────


def _org_out(org: models.Organization, role: str | None) -> OrgOut:
    return OrgOut(id=org.id, name=org.name, slug=org.slug, created_at=org.created_at, role=role)


@router.get("", response_model=list[OrgOut])
def list_orgs(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    my_roles = {
        om.org_id: om.role
        for om in db.query(models.OrganizationMember).filter(
            models.OrganizationMember.user_id == user.id
        )
    }
    if is_admin(user):
        orgs = db.query(models.Organization).order_by(models.Organization.name).all()
        return [_org_out(o, my_roles.get(o.id)) for o in orgs]
    if not my_roles:
        return []
    orgs = (
        db.query(models.Organization)
        .filter(models.Organization.id.in_(my_roles.keys()))
        .order_by(models.Organization.name)
        .all()
    )
    return [_org_out(o, my_roles.get(o.id)) for o in orgs]


@router.post("", status_code=201, response_model=OrgOut)
def create_org(
    body: OrgCreate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    if not _SLUG_RE.match(body.slug):
        raise HTTPException(
            400, "Invalid slug. Use lowercase alphanumeric with hyphens, 3-50 chars."
        )
    from ..core.plan import check_org_limit

    if not check_org_limit(db):
        raise HTTPException(
            402,
            "Multiple organizations require the Pro plan or higher. "
            "Upgrade to run more than one organization on this instance.",
        )
    if db.query(models.Organization).filter(models.Organization.slug == body.slug).first():
        raise HTTPException(409, "Slug already taken")
    org = models.Organization(
        id=new_id("org"), name=body.name, slug=body.slug, created_at=ts_now()
    )
    db.add(org)
    membership = models.OrganizationMember(
        id=new_id("om"), org_id=org.id, user_id=user.id, role=MemberRole.OWNER, created_at=ts_now()
    )
    db.add(membership)
    db.commit()
    db.refresh(org)
    return org


@router.get("/{org_id}", response_model=OrgOut)
def get_org(
    org_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_org_member(org_id, user, db)
    org = db.query(models.Organization).filter(models.Organization.id == org_id).first()
    if not org:
        raise HTTPException(404, "Organization not found")
    om = (
        db.query(models.OrganizationMember)
        .filter(
            models.OrganizationMember.org_id == org_id,
            models.OrganizationMember.user_id == user.id,
        )
        .first()
    )
    return _org_out(org, om.role if om else None)


@router.patch("/{org_id}", response_model=OrgOut)
def update_org(
    org_id: str,
    body: OrgUpdate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_org_admin(org_id, user, db)
    org = db.query(models.Organization).filter(models.Organization.id == org_id).first()
    if not org:
        raise HTTPException(404, "Organization not found")
    if body.name is not None:
        org.name = body.name
    if body.slug is not None:
        if not _SLUG_RE.match(body.slug):
            raise HTTPException(400, "Invalid slug")
        if (
            db.query(models.Organization)
            .filter(models.Organization.slug == body.slug, models.Organization.id != org_id)
            .first()
        ):
            raise HTTPException(409, "Slug already taken")
        org.slug = body.slug
    db.commit()
    db.refresh(org)
    return org


@router.delete("/{org_id}", status_code=204)
def delete_org(
    org_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_org_admin(org_id, user, db)
    org = db.query(models.Organization).filter(models.Organization.id == org_id).first()
    if not org:
        raise HTTPException(404, "Organization not found")
    db.query(models.TeamMember).filter(
        models.TeamMember.team_id.in_(db.query(models.Team.id).filter(models.Team.org_id == org_id))
    ).delete(synchronize_session=False)
    db.query(models.Team).filter(models.Team.org_id == org_id).delete(synchronize_session=False)
    db.query(models.OrganizationMember).filter(models.OrganizationMember.org_id == org_id).delete(
        synchronize_session=False
    )
    db.delete(org)
    db.commit()


# ── Organization Members ─────────────────────────────────────────────


@router.get("/{org_id}/members", response_model=list[OrgMemberOut])
def list_org_members(
    org_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_org_member(org_id, user, db)
    rows = (
        db.query(models.OrganizationMember, models.User)
        .join(models.User, models.OrganizationMember.user_id == models.User.id)
        .filter(models.OrganizationMember.org_id == org_id)
        .all()
    )
    return [
        OrgMemberOut(user_id=m.user_id, username=u.username, role=m.role, created_at=m.created_at)
        for m, u in rows
    ]


@router.post("/{org_id}/members", status_code=201, response_model=OrgMemberOut)
def add_org_member(
    org_id: str,
    body: OrgMemberAdd,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_org_admin(org_id, user, db)
    if MemberRole.coerce(body.role) is None:
        raise HTTPException(400, f"Invalid role. Valid: {MemberRole.values()}")
    check_member_role_allowed(body.role, db)
    # Same grant-ceiling rule as create_org_user: an org admin may never
    # hand out (or upgrade someone to) a role outranking their own —
    # otherwise a non-owner admin could promote a peer to owner.
    if org_role_rank(body.role) > caller_org_rank(db, org_id, user):
        raise HTTPException(403, "Cannot grant a role higher than your own")
    uid = body.user_id
    if not uid and body.username:
        found = (
            db.query(models.User)
            .filter(models.User.username == body.username, models.User.active)
            .first()
        )
        if not found:
            raise HTTPException(404, "User not found")
        uid = found.id
    if not uid:
        raise HTTPException(400, "user_id or username required")
    target = db.query(models.User).filter(models.User.id == uid, models.User.active).first()
    if not target:
        raise HTTPException(404, "User not found")
    existing = (
        db.query(models.OrganizationMember)
        .filter(
            models.OrganizationMember.org_id == org_id,
            models.OrganizationMember.user_id == uid,
        )
        .first()
    )
    if not existing:
        from ..core.plan import check_member_limit

        if not check_member_limit(org_id, db):
            raise HTTPException(
                402, "Member limit reached for your plan. Upgrade to add more members."
            )
    if existing:
        old_role = existing.role
        existing.role = body.role
        log_action(
            db,
            action=ACT_MEMBER_ROLE_CHANGE,
            actor_id=user.id,
            actor_name=user.username,
            target_type="org_member",
            target_id=uid,
            org_id=org_id,
            detail={"org_id": org_id, "from_role": old_role, "to_role": body.role},
        )
        db.commit()
        db.refresh(existing)
        out = OrgMemberOut(
            user_id=existing.user_id,
            username=target.username,
            role=existing.role,
            created_at=existing.created_at,
        )
        _bcast_org_member(org_id, "role_change", out.model_dump())
        return out
    m = models.OrganizationMember(
        id=new_id("om"), org_id=org_id, user_id=uid, role=body.role, created_at=ts_now()
    )
    db.add(m)
    log_action(
        db,
        action=ACT_MEMBER_ADD,
        actor_id=user.id,
        actor_name=user.username,
        target_type="org_member",
        target_id=uid,
        org_id=org_id,
        detail={"org_id": org_id, "role": body.role},
    )
    db.commit()
    db.refresh(m)
    out = OrgMemberOut(
        user_id=m.user_id, username=target.username, role=m.role, created_at=m.created_at
    )
    _bcast_org_member(org_id, "add", out.model_dump())
    return out


@router.patch("/{org_id}/members/{target_uid}", response_model=OrgMemberOut)
def update_org_member_role(
    org_id: str,
    target_uid: str,
    body: OrgMemberAdd,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    """Change an existing org member's role. Previously the only way to
    change a role after initial add was to re-POST the same upsert-style
    /members endpoint — not discoverable, and not what the org management
    UI called. Same grant-ceiling rule as add/create (2026-08-18)."""
    _require_org_admin(org_id, user, db)
    if MemberRole.coerce(body.role) is None:
        raise HTTPException(400, f"Invalid role. Valid: {MemberRole.values()}")
    check_member_role_allowed(body.role, db)
    if org_role_rank(body.role) > caller_org_rank(db, org_id, user):
        raise HTTPException(403, "Cannot grant a role higher than your own")
    existing = (
        db.query(models.OrganizationMember)
        .filter(
            models.OrganizationMember.org_id == org_id,
            models.OrganizationMember.user_id == target_uid,
        )
        .first()
    )
    if not existing:
        raise HTTPException(404, "Member not found")
    if existing.role == MemberRole.OWNER.value and body.role != MemberRole.OWNER.value:
        owner_count = (
            db.query(models.OrganizationMember)
            .filter(
                models.OrganizationMember.org_id == org_id,
                models.OrganizationMember.role == MemberRole.OWNER.value,
            )
            .count()
        )
        if owner_count <= 1:
            raise HTTPException(400, "Cannot demote the last owner")
    target = db.query(models.User).filter(models.User.id == target_uid).first()
    old_role = existing.role
    existing.role = body.role
    log_action(
        db,
        action=ACT_MEMBER_ROLE_CHANGE,
        actor_id=user.id,
        actor_name=user.username,
        target_type="org_member",
        target_id=target_uid,
        org_id=org_id,
        detail={"org_id": org_id, "from_role": old_role, "to_role": body.role},
    )
    db.commit()
    db.refresh(existing)
    out = OrgMemberOut(
        user_id=existing.user_id,
        username=target.username if target else "",
        role=existing.role,
        created_at=existing.created_at,
    )
    _bcast_org_member(org_id, "role_change", out.model_dump())
    return out


@router.post("/{org_id}/users", status_code=201, response_model=OrgMemberOut)
def create_org_user(
    org_id: str,
    body: OrgUserCreate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    """Create a brand-new platform user and add them straight into this
    org. Lets an org's own owner/admin/manager/team_lead onboard people
    without needing a platform_admin for every hire — previously user
    creation was exposed only via /api/admin/users, gated to
    platform_admin, so org-level roles had no way to create accounts at
    all (2026-08-18)."""
    require_org_user_manager(db, org_id, user)
    if MemberRole.coerce(body.role) is None:
        raise HTTPException(400, f"Invalid role. Valid: {MemberRole.values()}")
    check_member_role_allowed(body.role, db)
    # A caller may never hand out a role outranking their own — otherwise
    # e.g. a team_lead could create a fresh "admin" account, which is a
    # privilege escalation (flagged by security review 2026-08-18; the
    # original check only special-cased "owner" and left every other
    # elevated role unchecked against the caller's own rank).
    if org_role_rank(body.role) > caller_org_rank(db, org_id, user):
        raise HTTPException(403, "Cannot grant a role higher than your own")
    uname = body.username.strip()
    if not uname:
        raise HTTPException(400, "username is required")
    if db.query(models.User).filter(models.User.username == uname).first():
        raise HTTPException(409, "A user with this username already exists")
    from ..core.plan import check_member_limit

    if not check_member_limit(org_id, db):
        raise HTTPException(402, "Member limit reached for your plan. Upgrade to add more members.")
    try:
        validate_password_strength(body.password)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    new_user = models.User(
        id=new_id("u"),
        username=uname,
        display_name=(body.display_name or uname).strip(),
        password_hash=hash_password(body.password),
        role=UserRole.USER.value,  # org-scoped creation can never mint a platform_admin
        created_at=ts_now(),
        active=True,
    )
    db.add(new_user)
    member = models.OrganizationMember(
        id=new_id("om"), org_id=org_id, user_id=new_user.id, role=body.role, created_at=ts_now()
    )
    db.add(member)
    log_action(
        db,
        action=ACT_MEMBER_ADD,
        actor_id=user.id,
        actor_name=user.username,
        target_type="org_member",
        target_id=new_user.id,
        org_id=org_id,
        detail={"org_id": org_id, "role": body.role, "created_new_user": True},
    )
    db.commit()
    db.refresh(member)
    out = OrgMemberOut(
        user_id=new_user.id,
        username=new_user.username,
        role=member.role,
        created_at=member.created_at,
    )
    _bcast_org_member(org_id, "add", out.model_dump())
    return out


@router.delete("/{org_id}/members/{target_uid}", status_code=204)
def remove_org_member(
    org_id: str,
    target_uid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_org_admin(org_id, user, db)
    m = (
        db.query(models.OrganizationMember)
        .filter(
            models.OrganizationMember.org_id == org_id,
            models.OrganizationMember.user_id == target_uid,
        )
        .first()
    )
    if not m:
        raise HTTPException(404, "Member not found")
    if m.role == MemberRole.OWNER:
        owner_count = (
            db.query(models.OrganizationMember)
            .filter(
                models.OrganizationMember.org_id == org_id,
                models.OrganizationMember.role == MemberRole.OWNER,
            )
            .count()
        )
        if owner_count <= 1:
            raise HTTPException(400, "Cannot remove the last owner")
    db.delete(m)
    log_action(
        db,
        action=ACT_MEMBER_REMOVE,
        actor_id=user.id,
        actor_name=user.username,
        target_type="org_member",
        target_id=target_uid,
        org_id=org_id,
        detail={"org_id": org_id, "role": m.role},
    )
    db.commit()
    _bcast_org_member(org_id, "remove", {"user_id": target_uid})


# ── Teams ────────────────────────────────────────────────────────────


@router.get("/{org_id}/teams", response_model=list[TeamOut])
def list_teams(
    org_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_org_member(org_id, user, db)
    return (
        db.query(models.Team).filter(models.Team.org_id == org_id).order_by(models.Team.name).all()
    )


@router.post("/{org_id}/teams", status_code=201, response_model=TeamOut)
def create_team(
    org_id: str,
    body: TeamCreate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_org_admin(org_id, user, db)
    team = models.Team(id=new_id("tm"), org_id=org_id, name=body.name, created_at=ts_now())
    db.add(team)
    tm = models.TeamMember(
        id=new_id("tmm"),
        team_id=team.id,
        user_id=user.id,
        role=MemberRole.TEAM_LEAD,
        default_project_role=MemberRole.EDITOR.value,
        created_at=ts_now(),
    )
    db.add(tm)
    db.commit()
    db.refresh(team)
    return team


@router.delete("/{org_id}/teams/{team_id}", status_code=204)
def delete_team(
    org_id: str,
    team_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_org_admin(org_id, user, db)
    team = (
        db.query(models.Team)
        .filter(models.Team.id == team_id, models.Team.org_id == org_id)
        .first()
    )
    if not team:
        raise HTTPException(404, "Team not found")
    db.query(models.TeamMember).filter(models.TeamMember.team_id == team_id).delete(
        synchronize_session=False
    )
    db.delete(team)
    db.commit()




def _require_team_in_org(db: Session, org_id: str, team_id: str) -> "models.Team":
    """Security audit 2026-10-09 (M-6): team endpoints resolved the team by
    id alone, so a member of org A could read — and an org-admin of org A
    could modify — the roster of a team belonging to org B. Every team
    endpoint must confirm the team belongs to the org in the path."""
    team = (
        db.query(models.Team)
        .filter(models.Team.id == team_id, models.Team.org_id == org_id)
        .first()
    )
    if not team:
        raise HTTPException(404, "Team not found")
    return team

@router.get("/{org_id}/teams/{team_id}/members", response_model=list[TeamMemberOut])
def list_team_members(
    org_id: str,
    team_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_org_member(org_id, user, db)
    rows = (
        db.query(models.TeamMember, models.User)
        .join(models.User, models.TeamMember.user_id == models.User.id)
        .filter(models.TeamMember.team_id == team_id)
        .all()
    )
    return [
        TeamMemberOut(
            user_id=m.user_id,
            username=u.username,
            role=m.role,
            default_project_role=m.default_project_role,
            created_at=m.created_at,
        )
        for m, u in rows
    ]


@router.post("/{org_id}/teams/{team_id}/members", status_code=201, response_model=TeamMemberOut)
def add_team_member(
    org_id: str,
    team_id: str,
    body: TeamMemberAdd,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_org_admin(org_id, user, db)
    if MemberRole.coerce(body.role) is None:
        raise HTTPException(400, f"Invalid role. Valid: {MemberRole.values()}")
    check_member_role_allowed(body.role, db)
    team = (
        db.query(models.Team)
        .filter(models.Team.id == team_id, models.Team.org_id == org_id)
        .first()
    )
    if not team:
        raise HTTPException(404, "Team not found")
    uid = body.user_id
    if not uid and body.username:
        found = (
            db.query(models.User)
            .filter(models.User.username == body.username, models.User.active)
            .first()
        )
        if not found:
            raise HTTPException(404, "User not found")
        uid = found.id
    if not uid:
        raise HTTPException(400, "user_id or username required")
    target = db.query(models.User).filter(models.User.id == uid, models.User.active).first()
    if not target:
        raise HTTPException(404, "User not found")
    existing = (
        db.query(models.TeamMember)
        .filter(
            models.TeamMember.team_id == team_id,
            models.TeamMember.user_id == uid,
        )
        .first()
    )
    if existing:
        old_role = existing.role
        existing.role = body.role
        if body.default_project_role:
            existing.default_project_role = body.default_project_role
        log_action(
            db,
            action=ACT_MEMBER_ROLE_CHANGE,
            actor_id=user.id,
            actor_name=user.username,
            target_type="team_member",
            target_id=uid,
            org_id=org_id,
            detail={
                "org_id": org_id,
                "team_id": team_id,
                "from_role": old_role,
                "to_role": body.role,
            },
        )
        db.commit()
        db.refresh(existing)
        out = TeamMemberOut(
            user_id=existing.user_id,
            username=target.username,
            role=existing.role,
            default_project_role=existing.default_project_role,
            created_at=existing.created_at,
        )
        _bcast_org_member(org_id, "team_role_change", {"team_id": team_id, **out.model_dump()})
        return out
    tm = models.TeamMember(
        id=new_id("tmm"),
        team_id=team_id,
        user_id=uid,
        role=body.role,
        default_project_role=body.default_project_role or MemberRole.VIEWER.value,
        created_at=ts_now(),
    )
    db.add(tm)
    log_action(
        db,
        action=ACT_MEMBER_ADD,
        actor_id=user.id,
        actor_name=user.username,
        target_type="team_member",
        target_id=uid,
        org_id=org_id,
        detail={"org_id": org_id, "team_id": team_id, "role": body.role},
    )
    db.commit()
    db.refresh(tm)
    out = TeamMemberOut(
        user_id=tm.user_id,
        username=target.username,
        role=tm.role,
        default_project_role=tm.default_project_role,
        created_at=tm.created_at,
    )
    _bcast_org_member(org_id, "team_add", {"team_id": team_id, **out.model_dump()})
    return out


@router.delete("/{org_id}/teams/{team_id}/members/{target_uid}", status_code=204)
def remove_team_member(
    org_id: str,
    team_id: str,
    target_uid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_org_admin(org_id, user, db)
    _require_team_in_org(db, org_id, team_id)
    tm = (
        db.query(models.TeamMember)
        .filter(
            models.TeamMember.team_id == team_id,
            models.TeamMember.user_id == target_uid,
        )
        .first()
    )
    if not tm:
        raise HTTPException(404, "Team member not found")
    db.delete(tm)
    log_action(
        db,
        action=ACT_MEMBER_REMOVE,
        actor_id=user.id,
        actor_name=user.username,
        target_type="team_member",
        target_id=target_uid,
        org_id=org_id,
        detail={"org_id": org_id, "team_id": team_id, "role": tm.role},
    )
    db.commit()
    _bcast_org_member(org_id, "team_remove", {"team_id": team_id, "user_id": target_uid})
