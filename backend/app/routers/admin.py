from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.deps import require_admin
from ..core.enums import UserRole
from ..core.security import hash_password
from ..core.utils import new_id, ts_now
from ..database import get_db

router = APIRouter(
    prefix="/api/admin",
    tags=["admin"],
    responses={
        400: {"description": "Bad request"},
        404: {"description": "Not found"},
        409: {"description": "Conflict"},
    },
)


@router.get("/outbound-proxy")
def get_outbound_proxy(
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    """Current outbound proxy config (values are URLs; secrets-free)."""
    from ..core.outbound import SETTING_KEY

    item = db.query(models.GlobalSetting).filter(models.GlobalSetting.key == SETTING_KEY).first()
    return (item.value if item and isinstance(item.value, dict) else {}) or {}


@router.put("/outbound-proxy")
def set_outbound_proxy(
    body: dict,
    db: Session = Depends(get_db),
    user=Depends(require_admin),
):
    """Configure the outbound proxy for all platform egress.

    Body: {"http": "http://proxy:3128", "https": "...", "no_proxy": "..."}
    Takes effect for new outbound connections after a backend restart
    (env vars are read per-connection by httpx/requests, so most clients
    pick it up immediately; kubectl subprocesses inherit at spawn time).
    Set {} to disable. OUTBOUND_PROXY env var, when present, overrides this.
    """
    import re

    from sqlalchemy.orm.attributes import flag_modified

    from ..core.outbound import SETTING_KEY, apply_outbound_proxy

    cfg = {k: str(body.get(k) or "").strip() for k in ("http", "https", "no_proxy")}
    url_re = re.compile(r"^(http|https|socks5(h)?|socks4a?)://[\w.\-:\[\]@]+(:\d+)?(/.*)?$")
    for k in ("http", "https"):
        if cfg[k] and not url_re.match(cfg[k]):
            raise HTTPException(400, f"invalid {k} proxy URL: {cfg[k]}")
    value = {k: v for k, v in cfg.items() if v}
    item = db.query(models.GlobalSetting).filter(models.GlobalSetting.key == SETTING_KEY).first()
    if value:
        if item:
            item.value = value
            flag_modified(item, "value")
        else:
            item = models.GlobalSetting(key=SETTING_KEY, value=value)
            db.add(item)
    elif item:
        db.delete(item)
    db.commit()
    apply_outbound_proxy(db)
    return {"ok": True, "outbound_proxy": value, "effective": bool(value or __import__("os").environ.get("OUTBOUND_PROXY"))}


@router.get("/users")
def admin_list_users(
    admin: Annotated[models.User, Depends(require_admin)],
    db: Annotated[Session, Depends(get_db)],
):
    return [
        schemas.UserOut.model_validate(u)
        for u in db.query(models.User).order_by(models.User.created_at).all()
    ]


@router.post("/users", status_code=201, responses={409: {"description": "Conflict"}})
def admin_create_user(
    body: schemas.CreateUserRequest,
    admin: Annotated[models.User, Depends(require_admin)],
    db: Annotated[Session, Depends(get_db)],
):
    if db.query(models.User).filter(models.User.username == body.username.strip()).first():
        raise HTTPException(409, "A user with this username already exists")
    email_norm = (body.email or "").strip().lower() or None
    if email_norm and db.query(models.User).filter(models.User.email == email_norm).first():
        raise HTTPException(409, "A user with this email already exists")
    from ..core.security import validate_password_strength

    try:
        validate_password_strength(body.password)
    except ValueError as e:
        raise HTTPException(400, str(e))
    user = models.User(
        id=new_id("u"),
        username=body.username.strip(),
        email=email_norm,
        display_name=(body.display_name or body.username).strip(),
        password_hash=hash_password(body.password),
        role=body.role,
        created_at=ts_now(),
        active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return schemas.UserOut.model_validate(user)


@router.patch(
    "/users/{uid}",
    responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}},
)
def admin_update_user(
    uid: str,
    body: schemas.UpdateUserRequest,
    admin: Annotated[models.User, Depends(require_admin)],
    db: Annotated[Session, Depends(get_db)],
):
    user = db.query(models.User).filter(models.User.id == uid).first()
    if not user:
        raise HTTPException(404, "User not found")
    if body.role is not None:
        if uid == admin.id and body.role != UserRole.PLATFORM_ADMIN.value:
            raise HTTPException(400, "You cannot remove your own administrator role")
        user.role = body.role
    if body.display_name is not None:
        user.display_name = body.display_name.strip()
    if body.email is not None:
        email_norm = body.email.strip().lower() or None
        if (
            email_norm
            and db.query(models.User)
            .filter(models.User.email == email_norm, models.User.id != uid)
            .first()
        ):
            raise HTTPException(409, "A user with this email already exists")
        user.email = email_norm
    if body.active is not None:
        if uid == admin.id and not body.active:
            raise HTTPException(400, "You cannot deactivate yourself")
        user.active = body.active
    if body.password:
        user.password_hash = hash_password(body.password)
    db.commit()
    db.refresh(user)
    return schemas.UserOut.model_validate(user)


@router.delete(
    "/users/{uid}",
    status_code=204,
    responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}},
)
def admin_delete_user(
    uid: str,
    admin: Annotated[models.User, Depends(require_admin)],
    db: Annotated[Session, Depends(get_db)],
):
    if uid == admin.id:
        raise HTTPException(400, "You cannot delete yourself")
    user = db.query(models.User).filter(models.User.id == uid).first()
    if not user:
        raise HTTPException(404, "User not found")
    db.delete(user)
    db.commit()
