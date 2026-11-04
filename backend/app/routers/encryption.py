"""
Phase 2.6 — Encryption key management API.
KEK rotation, DEK rotation per project.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models
from ..core.deps import get_current_user, is_admin, require_admin
from ..core.events import log_event
from ..core.utils import ts_now
from ..database import get_db

router = APIRouter(
    prefix="/api/system/encryption",
    tags=["encryption"],
    responses={403: {"description": "Forbidden"}},
)


class RotateDEKBody(BaseModel):
    project_id: str


class KeyInfo(BaseModel):
    project_id: str
    algorithm: str
    version: int
    created_at: str
    rotated_at: str | None


@router.get("/keys", response_model=list[KeyInfo])
def list_encryption_keys(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(require_admin)],
):
    rows = db.query(models.ProjectEncryptionKey).all()
    return [
        KeyInfo(
            project_id=r.project_id,
            algorithm=r.algorithm,
            version=r.version,
            created_at=r.created_at,
            rotated_at=r.rotated_at,
        )
        for r in rows
    ]


@router.post("/rotate-dek", response_model=KeyInfo)
def rotate_project_dek(
    body: RotateDEKBody,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    if not is_admin(user):
        from ..core.access import check_pid_access

        check_pid_access(db, body.project_id, user, "project.manage_members")

    from ..core.key_management import (
        PDEK_SENTINEL,
        decrypt_dek_with_kek,
        encrypt_dek_with_kek,
        generate_dek,
    )

    row = (
        db.query(models.ProjectEncryptionKey)
        .filter(
            models.ProjectEncryptionKey.project_id == body.project_id,
        )
        .first()
    )

    if row:
        old_dek = decrypt_dek_with_kek(row.dek_enc)
        new_dek = generate_dek()
        from cryptography.fernet import Fernet, InvalidToken

        old_f = Fernet(old_dek)
        new_f = Fernet(new_dek)

        migrated = 0
        failed = 0

        # Only rows actually protected by *this* project's current DEK
        # (the "__pdek__:" sentinel — see core.key_management) are in
        # scope for this rotation. Rows still on the legacy global-KEK
        # sentinel haven't been migrated to a per-project DEK yet (see the
        # data migration) — they aren't protected by this DEK, so leaving
        # them untouched here is correct, not a failure.
        creds = db.query(models.Cred).filter(models.Cred.pid == body.project_id).all()
        for c in creds:
            if c.secret and c.secret.startswith(PDEK_SENTINEL):
                try:
                    raw = old_f.decrypt(c.secret[len(PDEK_SENTINEL) :].encode()).decode()
                    c.secret = f"{PDEK_SENTINEL}{new_f.encrypt(raw.encode()).decode()}"
                    migrated += 1
                except InvalidToken:
                    failed += 1

        secrets = (
            db.query(models.ProjectSecret)
            .filter(models.ProjectSecret.project_id == body.project_id)
            .all()
        )
        for s in secrets:
            if s.value_enc and s.value_enc.startswith(PDEK_SENTINEL):
                try:
                    raw = old_f.decrypt(s.value_enc[len(PDEK_SENTINEL) :].encode()).decode()
                    s.value_enc = f"{PDEK_SENTINEL}{new_f.encrypt(raw.encode()).decode()}"
                    migrated += 1
                except InvalidToken:
                    failed += 1

        if failed:
            # A value that claims to be protected by this project's
            # *current* DEK (the sentinel says so) but can't be decrypted
            # with it is a real problem (corruption, or a DEK/ciphertext
            # mismatch bug) — bumping the version and reporting success
            # here would tell the operator their secrets are protected by
            # the new key when they demonstrably are not. Fail loudly and
            # leave the DEK and all data untouched (security audit finding
            # F12).
            db.rollback()
            raise HTTPException(
                500,
                f"DEK rotation aborted: {failed} of {failed + migrated} secret(s) for "
                f"project {body.project_id} are marked as protected by the current "
                "per-project DEK but could not be decrypted with it, so nothing was "
                "re-encrypted. No key material was changed.",
            )

        row.dek_enc = encrypt_dek_with_kek(new_dek)
        row.version += 1
        row.rotated_at = ts_now()
    else:
        new_dek = generate_dek()
        row = models.ProjectEncryptionKey(
            project_id=body.project_id,
            dek_enc=encrypt_dek_with_kek(new_dek),
            created_at=ts_now(),
            version=1,
        )
        db.add(row)

    log_event(
        db,
        body.project_id,
        user.username,
        "encryption",
        "dek_rotate",
        f"DEK rotated to version {row.version}",
        {"version": row.version},
    )
    db.commit()
    db.refresh(row)
    return KeyInfo(
        project_id=row.project_id,
        algorithm=row.algorithm,
        version=row.version,
        created_at=row.created_at,
        rotated_at=row.rotated_at,
    )
