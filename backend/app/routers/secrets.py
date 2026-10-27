"""
Project Secrets Vault API — SSH keys, VPN configs, API tokens, certificates.
"""

from datetime import UTC
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models
from ..core.access import check_pid_access
from ..core.deps import get_current_user, is_admin
from ..core.events import log_event
from ..core.key_management import decrypt_for_project, encrypt_for_project
from ..core.permissions import PERM_SECRETS_MANAGE, PERM_SECRETS_READ
from ..core.utils import new_id, ts_now
from ..database import get_db

router = APIRouter(
    prefix="/api/projects/{pid}/secrets",
    tags=["secrets"],
    responses={
        400: {"description": "Bad request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)

SECRET_KINDS = {"ssh_key", "vpn_config", "api_token", "password", "cert"}


class SecretCreate(BaseModel):
    kind: str
    name: str
    value: str = ""
    issued_to: str | None = None
    expires_at: str | None = None
    auto_revoke_on_close: bool = True
    meta: dict = {}


class SecretUpdate(BaseModel):
    name: str | None = None
    value: str | None = None
    expires_at: str | None = None
    meta: dict | None = None


class SecretOut(BaseModel):
    id: str
    project_id: str
    kind: str
    name: str
    issued_to: str | None
    issued_at: str
    expires_at: str | None
    revoked_at: str | None
    auto_revoke_on_close: bool
    status: str
    meta: dict


class SSHKeyGenerate(BaseModel):
    name: str = "SSH Key"
    issued_to: str | None = None
    expires_at: str | None = None


def _secret_status(s: models.ProjectSecret) -> str:
    if s.revoked_at:
        return "revoked"
    if s.expires_at:
        try:
            from datetime import datetime

            exp = datetime.fromisoformat(s.expires_at.replace("Z", "+00:00"))
            if datetime.now(UTC) > exp:
                return "expired"
        except (ValueError, AttributeError):
            pass
    return "active"


def _to_out(s: models.ProjectSecret) -> SecretOut:
    return SecretOut(
        id=s.id,
        project_id=s.project_id,
        kind=s.kind,
        name=s.name,
        issued_to=s.issued_to,
        issued_at=s.issued_at,
        expires_at=s.expires_at,
        revoked_at=s.revoked_at,
        auto_revoke_on_close=s.auto_revoke_on_close,
        status=_secret_status(s),
        meta=s.meta or {},
    )


def _require_secret_admin(pid: str, user: models.User, db: Session):
    if is_admin(user):
        return
    check_pid_access(db, pid, user, PERM_SECRETS_MANAGE)


@router.get("", response_model=list[SecretOut])
def list_secrets(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, PERM_SECRETS_READ)
    secrets = (
        db.query(models.ProjectSecret)
        .filter(
            models.ProjectSecret.project_id == pid,
        )
        .order_by(
            models.ProjectSecret.created_at.desc()
            if hasattr(models.ProjectSecret, "created_at")
            else models.ProjectSecret.name
        )
        .all()
    )
    return [_to_out(s) for s in secrets]


@router.post("", status_code=201, response_model=SecretOut)
def create_secret(
    pid: str,
    body: SecretCreate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_secret_admin(pid, user, db)
    if body.kind not in SECRET_KINDS:
        raise HTTPException(400, f"Invalid kind. Valid: {SECRET_KINDS}")
    enc_value = encrypt_for_project(db, pid, body.value) if body.value else ""
    meta = dict(body.meta)
    meta.pop("public_key", None)
    meta.pop("fingerprint", None)
    s = models.ProjectSecret(
        id=new_id("sec"),
        project_id=pid,
        kind=body.kind,
        name=body.name,
        value_enc=enc_value,
        issued_to=body.issued_to,
        issued_at=ts_now(),
        expires_at=body.expires_at,
        auto_revoke_on_close=body.auto_revoke_on_close,
        meta=meta,
    )
    db.add(s)
    log_event(
        db,
        pid,
        user.username,
        "secret",
        "create",
        f"Secret created: {body.name} ({body.kind})",
        {"kind": body.kind},
    )
    db.commit()
    db.refresh(s)
    return _to_out(s)


@router.get("/{sid}", response_model=SecretOut)
def get_secret(
    pid: str,
    sid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, PERM_SECRETS_READ)
    s = (
        db.query(models.ProjectSecret)
        .filter(models.ProjectSecret.id == sid, models.ProjectSecret.project_id == pid)
        .first()
    )
    if not s:
        raise HTTPException(404, "Secret not found")
    return _to_out(s)


@router.patch("/{sid}", response_model=SecretOut)
def update_secret(
    pid: str,
    sid: str,
    body: SecretUpdate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_secret_admin(pid, user, db)
    s = (
        db.query(models.ProjectSecret)
        .filter(models.ProjectSecret.id == sid, models.ProjectSecret.project_id == pid)
        .first()
    )
    if not s:
        raise HTTPException(404, "Secret not found")
    if s.revoked_at:
        raise HTTPException(400, "Cannot update a revoked secret")
    if body.name is not None:
        s.name = body.name
    if body.value is not None:
        s.value_enc = encrypt_for_project(db, pid, body.value)
    if body.expires_at is not None:
        s.expires_at = body.expires_at
    if body.meta is not None:
        s.meta = body.meta
    log_event(
        db, pid, user.username, "secret", "update", f"Secret updated: {s.name}", {"kind": s.kind}
    )
    db.commit()
    db.refresh(s)
    return _to_out(s)


@router.delete("/{sid}", status_code=204)
def delete_secret(
    pid: str,
    sid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_secret_admin(pid, user, db)
    s = (
        db.query(models.ProjectSecret)
        .filter(models.ProjectSecret.id == sid, models.ProjectSecret.project_id == pid)
        .first()
    )
    if not s:
        raise HTTPException(404, "Secret not found")
    log_event(
        db,
        pid,
        user.username,
        "secret",
        "delete",
        f"Secret deleted: {s.name} ({s.kind})",
        {"kind": s.kind},
    )
    db.delete(s)
    db.commit()


@router.post("/{sid}/revoke", response_model=SecretOut)
def revoke_secret(
    pid: str,
    sid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_secret_admin(pid, user, db)
    s = (
        db.query(models.ProjectSecret)
        .filter(models.ProjectSecret.id == sid, models.ProjectSecret.project_id == pid)
        .first()
    )
    if not s:
        raise HTTPException(404, "Secret not found")
    if s.revoked_at:
        raise HTTPException(400, "Secret already revoked")
    s.revoked_at = ts_now()
    s.revoked_by = user.id
    log_event(
        db,
        pid,
        user.username,
        "secret",
        "revoke",
        f"Secret revoked: {s.name} ({s.kind})",
        {"kind": s.kind},
    )
    db.commit()
    db.refresh(s)
    return _to_out(s)


@router.get("/{sid}/download")
def download_secret(
    pid: str,
    sid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_secret_admin(pid, user, db)
    s = (
        db.query(models.ProjectSecret)
        .filter(models.ProjectSecret.id == sid, models.ProjectSecret.project_id == pid)
        .first()
    )
    if not s:
        raise HTTPException(404, "Secret not found")
    if s.revoked_at:
        raise HTTPException(400, "Secret is revoked")
    status = _secret_status(s)
    if status == "expired":
        raise HTTPException(400, "Secret has expired")
    value = decrypt_for_project(db, pid, s.value_enc)
    log_event(
        db,
        pid,
        user.username,
        "secret",
        "download",
        f"Secret downloaded: {s.name}",
        {"kind": s.kind},
    )
    db.commit()
    filename_map = {
        "ssh_key": "id_ed25519",
        "vpn_config": "wg0.conf",
        "api_token": "token.txt",
        "password": "password.txt",
        "cert": "cert.pem",
    }
    filename = s.meta.get("filename") or filename_map.get(s.kind, "secret.txt")
    return Response(
        content=value,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.post("/generate-ssh", status_code=201, response_model=SecretOut)
def generate_ssh_key(
    pid: str,
    body: SSHKeyGenerate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_secret_admin(pid, user, db)
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            NoEncryption,
            PrivateFormat,
            PublicFormat,
        )
    except ImportError:
        raise HTTPException(500, "cryptography library not available")

    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    priv_pem = private_key.private_bytes(
        Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()
    ).decode()
    pub_pem = public_key.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode()

    fingerprint = _ssh_fingerprint(pub_pem)

    enc_value = encrypt_for_project(db, pid, priv_pem)
    s = models.ProjectSecret(
        id=new_id("sec"),
        project_id=pid,
        kind="ssh_key",
        name=body.name,
        value_enc=enc_value,
        issued_to=body.issued_to,
        issued_at=ts_now(),
        expires_at=body.expires_at,
        auto_revoke_on_close=True,
        meta={"public_key": pub_pem, "fingerprint": fingerprint},
    )
    db.add(s)
    log_event(
        db,
        pid,
        user.username,
        "secret",
        "generate_ssh",
        f"SSH key generated: {body.name}",
        {"fingerprint": fingerprint},
    )
    db.commit()
    db.refresh(s)
    return _to_out(s)


def _ssh_fingerprint(pub_key: str) -> str:
    import base64
    import hashlib

    try:
        parts = pub_key.strip().split()
        if len(parts) >= 2:
            raw = base64.b64decode(parts[1])
            return f"SHA256:{base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip('=')}"
    except Exception:
        pass
    return "unknown"
