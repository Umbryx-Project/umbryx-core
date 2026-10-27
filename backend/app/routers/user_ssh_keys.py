"""User-profile SSH public keys (2026-09-02 workstation pool feature).

Users manage their own public keys; admins can list any user's keys for
the infrastructure-access page. Only public material is ever stored or
returned — private keys never leave the user's machine.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func as sa_func
from sqlalchemy.orm import Session

from .. import models
from ..core.deps import get_current_user, require_admin
from ..core.utils import new_id, ts_now
from ..core.workstation.pool import fingerprint_of, normalize_public_key
from ..database import get_db

router = APIRouter(prefix="/api/user/ssh-keys", tags=["user-ssh-keys"])
admin_router = APIRouter(prefix="/api/admin/users", tags=["user-ssh-keys"])


class SshKeyBody(BaseModel):
    name: str = ""
    public_key: str


def _list_keys(db: Session, user_id: str) -> list[dict]:
    active = {
        kid
        for kid, _ in db.query(
            models.WorkstationAccess.key_id, sa_func.count(models.WorkstationAccess.id)
        )
        .filter(models.WorkstationAccess.revoked_at.is_(None))
        .group_by(models.WorkstationAccess.key_id)
        .all()
    }
    keys = (
        db.query(models.UserSshKey)
        .filter(models.UserSshKey.user_id == user_id)
        .order_by(models.UserSshKey.created_at.desc())
        .all()
    )
    return [
        {
            "id": k.id,
            "name": k.name,
            "public_key": k.public_key,
            "fingerprint": k.fingerprint,
            "created_at": k.created_at,
            "in_use": k.id in active,
        }
        for k in keys
    ]


@router.get("")
def list_my_keys(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    return _list_keys(db, user.id)


@router.post("", status_code=201)
def add_my_key(
    body: SshKeyBody,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    try:
        normalized = normalize_public_key(body.public_key)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if not normalized or len(normalized.split()) < 2:
        raise HTTPException(400, "Not a valid OpenSSH public key line")
    duplicate = (
        db.query(models.UserSshKey)
        .filter(models.UserSshKey.user_id == user.id, models.UserSshKey.public_key == normalized)
        .first()
    )
    if duplicate:
        raise HTTPException(400, "This key is already added")
    key = models.UserSshKey(
        id=new_id("sshk"),
        user_id=user.id,
        name=(body.name or "").strip()[:100],
        public_key=normalized,
        fingerprint=fingerprint_of(normalized),
        created_at=ts_now(),
    )
    db.add(key)
    db.commit()
    db.refresh(key)
    return {
        "id": key.id,
        "name": key.name,
        "public_key": key.public_key,
        "fingerprint": key.fingerprint,
        "created_at": key.created_at,
        "in_use": False,
    }


@router.delete("/{key_id}", status_code=204)
def delete_my_key(
    key_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    key = (
        db.query(models.UserSshKey)
        .filter(models.UserSshKey.id == key_id, models.UserSshKey.user_id == user.id)
        .first()
    )
    if not key:
        raise HTTPException(404, "Key not found")
    active = (
        db.query(models.WorkstationAccess)
        .filter(
            models.WorkstationAccess.key_id == key_id,
            models.WorkstationAccess.revoked_at.is_(None),
        )
        .count()
    )
    if active:
        raise HTTPException(
            400,
            f"Key is currently granted on {active} machine(s) — revoke those accesses first",
        )
    db.delete(key)
    db.commit()


# ── Admin view (infrastructure-access page per user) ─────────────────


@admin_router.get("/{uid}/ssh-keys")
def list_user_keys(
    uid: str,
    db: Annotated[Session, Depends(get_db)],
    _admin: Annotated[models.User, Depends(require_admin)],
):
    return _list_keys(db, uid)
