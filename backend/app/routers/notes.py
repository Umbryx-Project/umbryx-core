import logging
from io import BytesIO
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, Response, UploadFile
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.access import check_object_access, check_pid_access, get_user_member_pids
from ..core.audit import ACT_NOTE_CREATE, ACT_NOTE_DELETE, log_action
from ..core.crypto import decrypt_str, encrypt_str, note_content_is_confidential
from ..core.deps import get_current_user, is_admin
from ..core.events import bcast, log_event
from ..core.permissions import PERM_NOTES_DELETE, PERM_NOTES_UPDATE
from ..core.storage import get_storage_backend
from ..core.sync_tracking import mark_local_change
from ..core.upload_guard import read_upload_capped
from ..core.utils import new_id, safe_upload_name, ts_now
from ..database import get_db

_MAX_UPLOAD = 50 * 1024 * 1024  # 50 MB

logger = logging.getLogger(__name__)

router = APIRouter(
    tags=["notes"],
    responses={
        404: {"description": "Not found"},
        413: {"description": "Payload too large"},
    },
)

_MSG_NOTE_NOT_FOUND = "Note not found"
_MSG_HOST_NOT_FOUND = "Host not found in this project"


def _check_host_in_project(db: Session, pid: str, host_id: str | None) -> None:
    if not host_id:
        return
    exists = (
        db.query(models.Host.id)
        .filter(models.Host.id == host_id, models.Host.pid == pid, models.Host.deleted_at.is_(None))
        .first()
    )
    if not exists:
        raise HTTPException(404, _MSG_HOST_NOT_FOUND)


def _note_out(note: models.Note) -> dict:
    data = schemas.Note.model_validate(note).model_dump()
    if note_content_is_confidential(data.get("tags") or []):
        data["content"] = decrypt_str(data.get("content") or "")
    return data


@router.get("/api/notes", response_model=list[schemas.Note])
def list_notes(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    pid: str | None = None,
    limit: Annotated[int, Query(ge=1, le=2000)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    if pid:
        check_pid_access(db, pid, user, "notes.read")
        q = db.query(models.Note).filter(models.Note.pid == pid)
        q = q.filter(models.Note.deleted_at.is_(None))
        total = q.count()
        response.headers["X-Total-Count"] = str(total)
        # Without an explicit ORDER BY, Postgres doesn't guarantee stable
        # row order across calls with LIMIT/OFFSET — on a project with
        # more notes than the page size, a just-created note could land
        # outside the first page unpredictably until a later query
        # happens to place it differently. `id` isn't creation-ordered
        # (random uuid4 prefix — see core/utils.new_id), but it's unique,
        # so pairing it with `ts` (which users can edit, hence not
        # unique) gives a fully deterministic, stable sort.
        q = q.order_by(models.Note.ts.desc(), models.Note.id.desc())
        notes = q.offset(offset).limit(limit).all()
        confidential_count = sum(
            1 for note in notes if note_content_is_confidential(note.tags or [])
        )
        # Serialize before audit commit — same expire-trigger as in
        # feature/perf-creds-serial. Each model_validate would otherwise
        # re-fetch every field of every note from the DB.
        out = [_note_out(note) for note in notes]
        if confidential_count:
            log_event(
                db,
                pid,
                getattr(user, "username", None),
                "audit",
                "read_confidential_notes",
                f"Confidential notes viewed ({confidential_count})",
                {"count": confidential_count},
            )
            db.commit()
        return out
    if is_admin(user):
        q = db.query(models.Note)
        q = q.filter(models.Note.deleted_at.is_(None))
        total = q.count()
        response.headers["X-Total-Count"] = str(total)
        q = q.order_by(models.Note.ts.desc(), models.Note.id.desc())
        return [_note_out(note) for note in q.offset(offset).limit(limit).all()]
    member_pids = get_user_member_pids(db, user)
    q = db.query(models.Note).filter(models.Note.pid.in_(member_pids))
    q = q.filter(models.Note.deleted_at.is_(None))
    total = q.count()
    response.headers["X-Total-Count"] = str(total)
    q = q.order_by(models.Note.ts.desc(), models.Note.id.desc())
    return [_note_out(note) for note in q.offset(offset).limit(limit).all()]


@router.post("/api/notes", response_model=schemas.Note, status_code=201)
def create_note(
    body: schemas.NoteCreate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, body.pid, user, "notes.create")
    _check_host_in_project(db, body.pid, body.host_id)
    payload = body.model_dump()
    if note_content_is_confidential(payload.get("tags") or []) and payload.get("content"):
        payload["content"] = encrypt_str(payload["content"])
    note = models.Note(id=new_id("n"), **payload)
    db.add(note)
    log_event(
        db,
        note.pid,
        getattr(request.state, "username", None),
        "note",
        "create",
        f"Note created: «{note.title}»",
        {"id": note.id},
    )
    log_action(
        db,
        action=ACT_NOTE_CREATE,
        actor_id=getattr(request.state, "uid", None),
        actor_name=getattr(request.state, "username", None),
        target_type="note",
        target_id=note.id,
        project_id=note.pid,
        ip_address=request.client.host if request.client else None,
    )
    mark_local_change(db, note.pid, "note", note.id)
    db.commit()
    db.refresh(note)
    payload = _note_out(note)
    bcast(note.pid, "note", "create", payload)
    return payload


@router.patch(
    "/api/notes/{nid}",
    response_model=schemas.Note,
    responses={404: {"description": "Not found"}, 409: {"description": "Conflict"}},
)
def update_note(
    nid: str,
    body: schemas.NoteUpdate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    note = db.query(models.Note).filter(models.Note.id == nid).first()
    if not note:
        raise HTTPException(404, _MSG_NOTE_NOT_FOUND)
    check_object_access(db, note.pid, user, PERM_NOTES_UPDATE)
    if body.client_version is not None and body.client_version != note.version:
        raise HTTPException(status_code=409, detail=schemas.Note.model_validate(note).model_dump())
    old_title = note.title
    # exclude_unset (not exclude_none) so a caller can explicitly send
    # `host_id: null` to unlink a note from its host — exclude_none would
    # silently drop that and make unlinking impossible via this endpoint.
    patch = body.model_dump(exclude_unset=True, exclude={"client_version"})
    if "host_id" in patch:
        _check_host_in_project(db, note.pid, patch["host_id"])
    next_tags = patch.get("tags", note.tags or [])
    next_content = patch.get("content", note.content or "")
    if "content" in patch or "tags" in patch:
        if note_content_is_confidential(next_tags) and next_content:
            patch["content"] = encrypt_str(decrypt_str(next_content))
        else:
            patch["content"] = decrypt_str(next_content)
    for k, v in patch.items():
        setattr(note, k, v)
    note.version += 1
    if body.title is not None and body.title != old_title:
        log_event(
            db,
            note.pid,
            getattr(request.state, "username", None),
            "note",
            "update",
            f"Note renamed: «{old_title}» → «{note.title}»",
            {"id": note.id},
        )
    mark_local_change(db, note.pid, "note", note.id)
    db.commit()
    db.refresh(note)
    payload = _note_out(note)
    bcast(note.pid, "note", "update", payload)
    return payload


@router.delete(
    "/api/notes/{nid}", response_model=schemas.Note, responses={404: {"description": "Not found"}}
)
def delete_note(
    nid: str,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    note = db.query(models.Note).filter(models.Note.id == nid).first()
    if not note:
        raise HTTPException(404, _MSG_NOTE_NOT_FOUND)
    check_object_access(db, note.pid, user, "notes.delete")
    pid = note.pid
    log_event(
        db,
        pid,
        getattr(request.state, "username", None),
        "note",
        "delete",
        f"Note deleted: «{note.title}»",
    )
    log_action(
        db,
        action=ACT_NOTE_DELETE,
        actor_id=getattr(request.state, "uid", None),
        actor_name=getattr(request.state, "username", None),
        target_type="note",
        target_id=note.id,
        project_id=pid,
        ip_address=request.client.host if request.client else None,
    )
    note.deleted_at = ts_now()
    db.commit()
    bcast(pid, "note", "delete", {"id": nid})
    return _note_out(note)


@router.post(
    "/api/notes/{nid}/restore",
    response_model=schemas.Note,
    responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}},
)
def restore_note(
    nid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    note = db.query(models.Note).filter(models.Note.id == nid).first()
    if not note:
        raise HTTPException(404, _MSG_NOTE_NOT_FOUND)
    check_object_access(db, note.pid, user, PERM_NOTES_DELETE)
    if note.deleted_at is None:
        raise HTTPException(400, "Note is not deleted")
    note.deleted_at = None
    db.commit()
    db.refresh(note)
    bcast(note.pid, "note", "update", schemas.Note.model_validate(note).model_dump())
    return _note_out(note)


@router.get(
    "/api/notes/{nid}/attachments",
    response_model=list[schemas.NoteAttachment],
    responses={404: {"description": "Not found"}},
)
def list_note_attachments(
    nid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    note = db.query(models.Note).filter(models.Note.id == nid).first()
    if not note:
        raise HTTPException(404, _MSG_NOTE_NOT_FOUND)
    check_object_access(db, note.pid, user, "notes.read")
    return db.query(models.NoteAttachment).filter(models.NoteAttachment.note_id == nid).all()


@router.post(
    "/api/notes/{nid}/attachments",
    response_model=schemas.NoteAttachment,
    status_code=201,
    responses={404: {"description": "Not found"}, 413: {"description": "Payload too large"}},
)
async def upload_note_attachment(
    nid: str,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    file: Annotated[UploadFile, File()],
):
    note = db.query(models.Note).filter(models.Note.id == nid).first()
    if not note:
        raise HTTPException(404, _MSG_NOTE_NOT_FOUND)
    check_object_access(db, note.pid, user, PERM_NOTES_UPDATE)
    safe_name = safe_upload_name(file.filename or "attachment.bin")
    att_id = new_id("att")
    ext = Path(safe_name).suffix
    disk_name = f"{att_id}{ext}"
    content = await read_upload_capped(file, _MAX_UPLOAD, request)
    storage = get_storage_backend()
    att_storage_path = await storage.save(note.pid, f"{nid}/{disk_name}", BytesIO(content))
    attachment = models.NoteAttachment(
        id=att_id,
        note_id=nid,
        pid=note.pid,
        filename=safe_name,
        content_type=file.content_type or "application/octet-stream",
        file_size=len(content),
        storage_path=att_storage_path,
        public_url=f"/api/uploads/{note.pid}/{nid}/{disk_name}",
        ts=ts_now(),
    )
    db.add(attachment)
    db.commit()
    db.refresh(attachment)
    bcast(
        note.pid,
        "note_attachment",
        "create",
        schemas.NoteAttachment.model_validate(attachment).model_dump(),
    )
    return attachment


@router.delete(
    "/api/attachments/{aid}", status_code=204, responses={404: {"description": "Not found"}}
)
async def delete_attachment(
    aid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    attachment = db.query(models.NoteAttachment).filter(models.NoteAttachment.id == aid).first()
    if not attachment:
        raise HTTPException(404, "Attachment not found")
    check_object_access(db, attachment.pid, user, PERM_NOTES_UPDATE)
    pid = attachment.pid
    note_id = attachment.note_id
    try:
        storage = get_storage_backend()
        await storage.delete(attachment.storage_path)
    except Exception as e:
        logger.warning("Failed to delete attachment file %s: %s", attachment.storage_path, e)
    db.delete(attachment)
    db.commit()
    bcast(pid, "note_attachment", "delete", {"id": aid, "note_id": note_id})
