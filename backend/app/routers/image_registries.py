from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from .. import models
from ..core.deps import get_current_user, is_admin
from ..core.image_registries import (
    add_image_registry,
    delete_image_registry,
    list_image_registries,
)
from ..core.org_access import get_org_role, require_org_admin
from ..database import get_db

router = APIRouter(prefix="/api/image-registries", tags=["image-registries"])


def _check_write_access(org_id: str | None, user: models.User, db: Session) -> None:
    """org_id given → caller must administer that org (or be platform_admin);
    org_id omitted → editing the platform-wide list, platform_admin only
    (unchanged legacy behavior)."""
    if org_id:
        require_org_admin(db, org_id, user)
    elif not is_admin(user):
        from ..core.errors import AppError

        raise AppError("admin_required", "Admin access required", status=403)


def _check_read_access(org_id: str | None, user: models.User, db: Session) -> None:
    """A registry list can include a private URL/username even with the
    password masked — an org's list must not be readable by an outsider
    just by guessing/enumerating its org_id (flagged by security review
    2026-08-18: this endpoint had no org-membership check at all)."""
    if org_id and not is_admin(user) and get_org_role(db, org_id, user.id) is None:
        from ..core.errors import AppError

        raise AppError("forbidden", "Not a member of this organization", status=403)


@router.get("")
async def registries_list(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    org_id: Annotated[str | None, Query()] = None,
):
    _check_read_access(org_id, user, db)
    return list_image_registries(db, org_id=org_id)


@router.post("")
async def registries_create(
    body: dict,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    org_id: Annotated[str | None, Query()] = None,
):
    _check_write_access(org_id, user, db)
    name = body.get("name", "").strip()
    url = body.get("url", "").strip()
    username = body.get("username", "").strip()
    password = body.get("password", "")
    if not name or not url:
        raise HTTPException(400, "name and url are required")
    return add_image_registry(name, url, username, password, db, org_id=org_id)


@router.delete("/{reg_id}")
async def registries_delete(
    reg_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    org_id: Annotated[str | None, Query()] = None,
):
    _check_write_access(org_id, user, db)
    if not delete_image_registry(reg_id, db, org_id=org_id):
        raise HTTPException(404, "Registry not found")
    return {"ok": True}
