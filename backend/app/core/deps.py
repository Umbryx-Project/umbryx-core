from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from .. import models
from ..database import get_db
from .enums import UserRole
from .errors import AppError
from .security import decode_access_token


def is_admin(user: "models.User | None") -> bool:
    return bool(user is not None and user.role == UserRole.PLATFORM_ADMIN.value)


def is_platform_admin(user: "models.User | None") -> bool:
    return is_admin(user)


def is_infra_admin(db: Session, user: "models.User | None") -> bool:
    """Org-scoped infra administrator: platform_admin, or a member with an
    org-admin-capable role (owner/admin/manager/team_lead) in ANY
    organization.

    Workstations / pool machines / SSH-executor targets / egress proxies
    are organization-level infrastructure, not project assets — their
    management must not depend on the caller's role in whichever project
    happens to be selected. This is the bar those endpoints use instead
    of the global require_admin.
    """
    if is_admin(user):
        return True
    if user is None:
        return False
    from .org_access import ORG_USER_MANAGER_ROLES

    roles = (
        db.query(models.OrganizationMember.role)
        .filter(models.OrganizationMember.user_id == user.id)
        .all()
    )
    return any(r[0] in ORG_USER_MANAGER_ROLES for r in roles)


def get_current_user(request: Request, db: Annotated[Session, Depends(get_db)]) -> models.User:
    uid = getattr(request.state, "uid", None)
    if not uid:
        raise AppError("unauthenticated", "Not authenticated", status=401)
    user = db.query(models.User).filter(models.User.id == uid, models.User.active).first()
    if not user:
        raise AppError("user_inactive", "User not found or inactive", status=401)
    return user


def require_admin(user: Annotated[models.User, Depends(get_current_user)]) -> models.User:
    if not is_admin(user):
        raise AppError("admin_required", "Admin access required", status=403)
    return user


async def require_infra_admin(
    user: Annotated[models.User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
) -> models.User:
    if not is_infra_admin(db, user):
        raise AppError("infra_admin_required", "Infra admin access required", status=403)
    return user


def is_global_viewer(user: "models.User | None") -> bool:
    return bool(user is not None and user.role == UserRole.VIEWER.value)


def decode_ws_token(token: str, db: Session) -> models.User | None:
    payload = decode_access_token(token)
    if not payload:
        return None
    uid = payload.get("sub")
    return db.query(models.User).filter(models.User.id == uid, models.User.active).first()
