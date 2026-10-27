import logging
from io import BytesIO
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, Response, UploadFile
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.access import check_object_access, check_pid_access, get_user_member_pids
from ..core.artifact_extractor import sha256_bytes as _sha256
from ..core.audit import ACT_LOOT_CREATE, ACT_LOOT_DELETE, ACT_LOOT_RESTORE, log_action
from ..core.crypto import (
    DecryptionError,
    decrypt_bytes,
    decrypt_str,
    encrypt_bytes,
    encrypt_str,
    is_encrypted,
    loot_value_is_sensitive,
)
from ..core.deps import get_current_user, is_admin, require_admin
from ..core.events import bcast, log_event
from ..core.permissions import PERM_LOOT_DELETE
from ..core.storage import get_storage_backend
from ..core.sync_tracking import mark_local_change
from ..core.upload_guard import read_upload_capped
from ..core.utils import new_id, safe_upload_name, ts_now
from ..database import get_db

logger = logging.getLogger(__name__)

MAX_UPLOAD = 50 * 1024 * 1024  # 50 MB

router = APIRouter(prefix="/api/loots", tags=["loots"])


def _loot_audit_label(loot: models.Loot) -> str:
    """Build a safe audit-timeline label for a loot entry.

    Security audit finding (2026-08-29): this used to decrypt the loot
    value and put up to 40 chars of the *decrypted secret* (e.g. most of
    an NTLM hash) into a plaintext audit-timeline entry. Encrypted values
    stay encrypted here — the label falls back to the description, or a
    generic placeholder if there isn't one. Unencrypted values (loot that
    was never classified as sensitive, e.g. scan output snippets) are
    still safe to preview as before.
    """
    value = loot.value or ""
    if value and not is_encrypted(value):
        preview = value[:40]
    else:
        preview = loot.description or "(sensitive value, not shown)"
    return f"[{loot.loot_type}]: {preview}"


def _loot_out(loot: models.Loot) -> dict:
    data = schemas.Loot.model_validate(loot).model_dump()
    if loot_value_is_sensitive(
        data.get("loot_type", ""),
        data.get("artifact_type", ""),
        data.get("filename", ""),
        getattr(loot, "storage_path", ""),
        data.get("public_url", ""),
    ):
        try:
            data["value"] = decrypt_str(data.get("value") or "")
        except DecryptionError:
            # Found live: a rotated/lost ENCRYPTION_KEY made the whole
            # GET /api/loots 500 on the first undecryptable row. A read
            # list must never die on legacy ciphertext — show a marker
            # so the operator knows which values need re-entry instead.
            logger.warning(
                "loot %s value undecryptable with the current key — showing marker",
                loot.id,
            )
            data["value"] = "[undecryptable: encryption key changed]"
    return data


@router.get(
    "",
    response_model=list[schemas.Loot],
    responses={404: {"description": "Not found"}, 413: {"description": "Payload too large"}},
)
def list_loots(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    pid: str | None = None,
    job_id: str | None = None,
    artifact_type: str | None = None,
    host_id: str | None = None,
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    if pid:
        check_pid_access(db, pid, user, "loot.read")
        q = db.query(models.Loot).filter(models.Loot.pid == pid)
        if job_id:
            q = q.filter(models.Loot.job_id == job_id)
        if artifact_type:
            q = q.filter(models.Loot.artifact_type == artifact_type)
        if host_id:
            q = q.filter(models.Loot.host_id == host_id)
        q = q.filter(models.Loot.deleted_at.is_(None))
        total = q.count()
        response.headers["X-Total-Count"] = str(total)
        loots = q.order_by(models.Loot.ts.desc()).offset(offset).limit(limit).all()
        sensitive_count = sum(
            1
            for loot in loots
            if loot_value_is_sensitive(
                loot.loot_type,
                loot.artifact_type,
                loot.filename,
                loot.storage_path,
                loot.public_url,
            )
        )
        # Serialize before the audit commit. db.commit() expires loaded
        # ORM instances by default, which would trigger a lazy reload on
        # every subsequent attribute access in _loot_out (same trap as
        # feature/perf-creds-serial).
        out = [_loot_out(loot) for loot in loots]
        if sensitive_count:
            log_event(
                db,
                pid,
                getattr(user, "username", None),
                "audit",
                "read_sensitive_loot",
                f"Sensitive loot viewed ({sensitive_count})",
                {"count": sensitive_count},
            )
            db.commit()
        return out
    if is_admin(user):
        q = db.query(models.Loot)
        if job_id:
            q = q.filter(models.Loot.job_id == job_id)
        q = q.filter(models.Loot.deleted_at.is_(None))
        total = q.count()
        response.headers["X-Total-Count"] = str(total)
        loots = q.order_by(models.Loot.ts.desc()).offset(offset).limit(limit).all()
        out = [_loot_out(loot) for loot in loots]
        # Security audit 2026-10-07 (M4): the pid-less branches used to skip
        # the read_sensitive_loot audit entirely even though _loot_out
        # decrypts sensitive values — admin/global listings decrypt just as
        # much as the project-scoped one and must leave the same trail.
        sensitive_count = sum(
            1
            for loot in loots
            if loot_value_is_sensitive(
                loot.loot_type,
                loot.artifact_type,
                loot.filename,
                loot.storage_path,
                loot.public_url,
            )
        )
        if sensitive_count:
            from ..core.system_log import log_operations

            log_operations(
                db,
                "loot.read_sensitive",
                user_id=user.id,
                detail={"count": sensitive_count, "scope": "admin_global"},
            )
            db.commit()
        return out
    member_pids = get_user_member_pids(db, user)
    q = db.query(models.Loot).filter(models.Loot.pid.in_(member_pids))
    q = q.filter(models.Loot.deleted_at.is_(None))
    total = q.count()
    response.headers["X-Total-Count"] = str(total)
    loots = q.order_by(models.Loot.ts.desc()).offset(offset).limit(limit).all()
    out = [_loot_out(loot) for loot in loots]
    sensitive_count = sum(
        1
        for loot in loots
        if loot_value_is_sensitive(
            loot.loot_type,
            loot.artifact_type,
            loot.filename,
            loot.storage_path,
            loot.public_url,
        )
    )
    if sensitive_count:
        from ..core.system_log import log_operations

        log_operations(
            db,
            "loot.read_sensitive",
            user_id=user.id,
            detail={"count": sensitive_count, "scope": "member_all_projects"},
        )
        db.commit()
    return out


@router.post(
    "",
    response_model=schemas.Loot,
    status_code=201,
    responses={404: {"description": "Not found"}, 413: {"description": "Payload too large"}},
)
def create_loot(
    body: schemas.LootCreate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, body.pid, user, "loot.create")
    payload = body.model_dump()
    if loot_value_is_sensitive(
        payload.get("loot_type", ""),
        payload.get("artifact_type", ""),
        payload.get("filename", ""),
        "",
        payload.get("public_url", ""),
    ) and payload.get("value"):
        payload["value"] = encrypt_str(payload["value"])
    loot = models.Loot(**payload, id=new_id("lt"), ts=ts_now())
    db.add(loot)
    log_event(
        db,
        loot.pid,
        getattr(request.state, "username", None),
        "loot",
        "create",
        _loot_audit_label(loot),
    )
    log_action(
        db,
        action=ACT_LOOT_CREATE,
        actor_id=getattr(request.state, "uid", None),
        actor_name=getattr(request.state, "username", None),
        target_type="loot",
        target_id=loot.id,
        project_id=loot.pid,
        ip_address=request.client.host if request.client else None,
    )
    mark_local_change(db, loot.pid, "loot", loot.id)
    db.commit()
    db.refresh(loot)
    payload = _loot_out(loot)
    bcast(loot.pid, "loot", "create", payload)
    return payload


@router.patch(
    "/{lid}",
    response_model=schemas.Loot,
    responses={404: {"description": "Not found"}, 413: {"description": "Payload too large"}},
)
def update_loot(
    lid: str,
    body: schemas.LootUpdate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    loot = db.query(models.Loot).filter(models.Loot.id == lid).first()
    if not loot:
        raise HTTPException(404)
    check_object_access(db, loot.pid, user, "loot.update")
    updates = body.model_dump(exclude_none=True)
    next_is_sensitive = loot_value_is_sensitive(
        updates.get("loot_type", loot.loot_type),
        updates.get("artifact_type", loot.artifact_type),
        updates.get("filename", loot.filename),
        updates.get("storage_path", loot.storage_path),
        updates.get("public_url", loot.public_url),
    )
    if "value" in updates or any(
        key in updates for key in ("loot_type", "artifact_type", "filename", "public_url")
    ):
        next_value = updates.get("value", loot.value or "")
        if next_is_sensitive and next_value:
            updates["value"] = encrypt_str(decrypt_str(next_value))
        else:
            updates["value"] = decrypt_str(next_value)
    for k, v in updates.items():
        setattr(loot, k, v)
    mark_local_change(db, loot.pid, "loot", loot.id)
    db.commit()
    db.refresh(loot)
    payload = _loot_out(loot)
    bcast(loot.pid, "loot", "update", payload)
    return payload


@router.delete(
    "/{lid}",
    response_model=schemas.Loot,
    responses={404: {"description": "Not found"}, 413: {"description": "Payload too large"}},
)
def delete_loot(
    lid: str,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    loot = db.query(models.Loot).filter(models.Loot.id == lid).first()
    if not loot:
        raise HTTPException(404)
    check_object_access(db, loot.pid, user, "loot.delete")
    pid = loot.pid
    log_event(
        db,
        pid,
        getattr(request.state, "username", None),
        "loot",
        "delete",
        f"Loot deleted: {_loot_audit_label(loot)}",
    )
    log_action(
        db,
        action=ACT_LOOT_DELETE,
        actor_id=getattr(request.state, "uid", None),
        actor_name=getattr(request.state, "username", None),
        target_type="loot",
        target_id=loot.id,
        project_id=pid,
        ip_address=request.client.host if request.client else None,
    )
    loot.deleted_at = ts_now()
    db.commit()
    bcast(pid, "loot", "delete", {"id": lid})
    return _loot_out(loot)


@router.post(
    "/{lid}/restore",
    response_model=schemas.Loot,
    responses={
        400: {"description": "Bad request"},
        404: {"description": "Not found"},
        413: {"description": "Payload too large"},
    },
)
def restore_loot(
    lid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    loot = db.query(models.Loot).filter(models.Loot.id == lid).first()
    if not loot:
        raise HTTPException(404, "Loot not found")
    check_object_access(db, loot.pid, user, PERM_LOOT_DELETE)
    if loot.deleted_at is None:
        raise HTTPException(400, "Loot is not deleted")
    loot.deleted_at = None
    log_action(
        db,
        action=ACT_LOOT_RESTORE,
        actor_id=user.id,
        actor_name=user.username,
        target_type="loot",
        target_id=loot.id,
        project_id=loot.pid,
    )
    db.commit()
    db.refresh(loot)
    bcast(loot.pid, "loot", "update", schemas.Loot.model_validate(loot).model_dump())
    return _loot_out(loot)


@router.post(
    "/{lid}/file",
    response_model=schemas.Loot,
    status_code=201,
    responses={404: {"description": "Not found"}, 413: {"description": "Payload too large"}},
)
async def upload_loot_file(
    lid: str,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    file: Annotated[UploadFile, File()],
):
    loot = db.query(models.Loot).filter(models.Loot.id == lid).first()
    if not loot:
        raise HTTPException(404, "Loot not found")
    check_object_access(db, loot.pid, user, "loot.update")
    safe_name = safe_upload_name(file.filename or "loot.bin")
    ext = Path(safe_name).suffix
    disk_name = f"{loot.id}{ext}"
    content = await read_upload_capped(file, MAX_UPLOAD, request)
    original_sha256 = _sha256(content)
    encrypted = encrypt_bytes(content)
    storage = get_storage_backend()
    loot.storage_path = await storage.save(loot.pid, f"loot/{disk_name}", BytesIO(encrypted))
    loot.filename = safe_name
    loot.content_type = file.content_type or "application/octet-stream"
    loot.file_size = len(content)
    loot.public_url = f"/api/uploads/{loot.pid}/loot/{disk_name}"
    loot.sha256 = original_sha256
    loot.artifact_type = "file"
    loot.file_encrypted = True
    # Extract document text (pdf/docx/xlsx/text) from the plaintext bytes for
    # content search — best-effort, never blocks the upload.
    from ..core.text_extract import extract_text

    loot.extracted_text = extract_text(content, safe_name, loot.content_type)
    if not loot.value:
        loot.value = safe_name
    if not loot.source_path:
        loot.source_path = f"/api/uploads/{loot.pid}/loot/{disk_name}"
    loot.loot_type = "file"
    db.commit()
    db.refresh(loot)
    payload = _loot_out(loot)
    log_event(
        db,
        loot.pid,
        getattr(request.state, "username", None),
        "loot",
        "upload",
        f"Loot file uploaded: {safe_name}",
    )
    db.commit()
    bcast(loot.pid, "loot", "update", payload)
    return loot


@router.post("/reindex-text")
async def reindex_loot_text(
    db: Annotated[Session, Depends(get_db)],
    _admin: Annotated[models.User, Depends(require_admin)],
    limit: int = Query(500, ge=1, le=5000),
):
    """Backfill extracted_text for already-uploaded document loot so their
    content becomes searchable. Platform-admin only (it decrypts files).
    Processes up to `limit` un-indexed file loots per call; returns how many
    were indexed and how many still remain."""
    from ..core.text_extract import extract_text

    q = (
        db.query(models.Loot)
        .filter(
            models.Loot.public_url != "",
            models.Loot.extracted_text == "",
            models.Loot.deleted_at.is_(None),
        )
    )
    remaining_before = q.count()
    storage = get_storage_backend()
    indexed = 0
    for loot in q.limit(limit).all():
        try:
            key = loot.public_url.replace("/api/uploads/", "", 1)
            data = await storage.load(key)
            if data is None:
                continue
            if loot.file_encrypted:
                data = decrypt_bytes(data)
            text = extract_text(data, loot.filename, loot.content_type)
            # Mark as processed even when no text (empty stays ""); use a
            # single space sentinel only if extraction yielded nothing, so we
            # don't re-scan binaries every run.
            loot.extracted_text = text or " "
            db.commit()
            if text:
                indexed += 1
        except Exception as exc:  # noqa: BLE001 — one bad file mustn't stop the batch
            logger.warning("reindex loot %s failed: %s", loot.id, exc)
            db.rollback()
    return {"indexed": indexed, "remaining_before": remaining_before, "batch": limit}
