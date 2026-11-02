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
def registries_list(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    org_id: Annotated[str | None, Query()] = None,
):
    _check_read_access(org_id, user, db)
    return list_image_registries(db, org_id=org_id)


@router.post("")
def registries_create(
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
    # SSRF-10 fix: registry login credentials are sent to this URL by the
    # server-side docker CLI — enforce scheme + hostname grammar at store time.
    from urllib.parse import urlparse as _up

    # Accept either a full http(s) URL or a docker-style bare host[:port]
    # (the docker CLI takes both; a scheme-less host is the SAFEST form —
    # no scheme confusion, no userinfo). Everything else is rejected.
    from ..core.net import is_valid_host_literal, is_valid_port

    _pu = _up(url if "//" in url else f"//{url}")
    try:
        _port = _pu.port  # urlparse RAISES on ports > 65535 — 400, not 500
    except ValueError:
        _port = -1
    _scheme_ok = _pu.scheme in ("", "http", "https")
    _host_ok = bool(_pu.hostname) and is_valid_host_literal(_pu.hostname)
    _port_ok = _port is None or is_valid_port(_port)
    _userinfo_ok = _pu.username is None and _pu.password is None
    if not (_scheme_ok and _host_ok and _port_ok and _userinfo_ok):
        raise HTTPException(400, "registry url must be a valid http(s) URL")
    _reg_host = _pu.hostname or ""
    _reg_port = _pu.port
    if not _reg_host or not is_valid_host_literal(_reg_host):
        raise HTTPException(400, "registry url must be a valid http(s) URL")
    from ..core.net import is_valid_port as _ivp

    if _reg_port is not None and not _ivp(_reg_port):
        raise HTTPException(400, "registry url must be a valid http(s) URL")
    return add_image_registry(name, url, username, password, db, org_id=org_id)


@router.delete("/{reg_id}")
def registries_delete(
    reg_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    org_id: Annotated[str | None, Query()] = None,
):
    _check_write_access(org_id, user, db)
    if not delete_image_registry(reg_id, db, org_id=org_id):
        raise HTTPException(404, "Registry not found")
    return {"ok": True}
