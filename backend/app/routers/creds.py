from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.access import check_object_access, check_pid_access, get_user_member_pids
from ..core.deps import get_current_user, is_admin
from ..core.errors import AppError
from ..core.events import bcast, log_event
from ..core.key_management import decrypt_for_project, encrypt_for_project
from ..core.limiter import limiter
from ..core.permissions import get_membership, get_permissions_for_role
from ..core.sync_tracking import mark_local_change
from ..core.utils import domains_match, new_id, normalize_domain
from ..database import get_db

router = APIRouter(prefix="/api/creds", tags=["creds"])


def _can_read_secret(user: models.User, pid: str, db: Session) -> bool:
    if is_admin(user):
        return True
    membership = get_membership(db, pid, user.id)
    if not membership:
        return False
    return "credentials.read_secret" in get_permissions_for_role(membership.role)


def _cred_out(cred: models.Cred, user: models.User, db: Session) -> dict:
    data = schemas.Cred.model_validate(cred).model_dump()
    if _can_read_secret(user, cred.pid, db):
        data["secret"] = decrypt_for_project(db, cred.pid, data["secret"])
    else:
        data["secret"] = ""
    return data


def _cred_schema_with_read_flag(
    cred: models.Cred, can_read_secret: bool, db: Session
) -> "schemas.Cred":
    """List-path variant — returns the Pydantic instance instead of a dict
    so FastAPI's response_model serializer doesn't re-validate the same
    payload twice. Caller pre-computes can_read_secret once per pid."""
    obj = schemas.Cred.model_validate(cred)
    obj.secret = decrypt_for_project(db, cred.pid, obj.secret) if can_read_secret else ""
    return obj


def _validate_domain_host_links(pid: str, domain: str, host_ids: list[str], db: Session):
    normalized_domain = normalize_domain(domain)
    if not normalized_domain or not host_ids:
        return
    hosts = db.query(models.Host).filter(models.Host.pid == pid, models.Host.id.in_(host_ids)).all()
    by_id = {host.id: host for host in hosts}
    missing = [hid for hid in host_ids if hid not in by_id]
    if missing:
        raise AppError(
            "host_not_found",
            f"Host not found: {missing[0]}",
            status=404,
            details={"host_id": missing[0]},
        )
    mismatched = [host for host in hosts if not domains_match(host.domain or "", normalized_domain)]
    if mismatched:
        labels = ", ".join((host.hostname or host.ip or host.id) for host in mismatched[:5])
        raise AppError(
            "cred_domain_mismatch",
            f"Domain credential cannot be linked to hosts from another domain: {labels}",
            status=400,
            details={"mismatched_host_ids": [h.id for h in mismatched]},
        )


@router.get("", response_model=list[schemas.Cred])
def list_creds(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    pid: str | None = None,
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    if pid:
        check_pid_access(db, pid, user, "credentials.read")
        q = db.query(models.Cred).filter(models.Cred.pid == pid)
    elif is_admin(user):
        q = db.query(models.Cred)
    else:
        member_pids = get_user_member_pids(db, user)
        q = db.query(models.Cred).filter(models.Cred.pid.in_(member_pids))
    total = q.count()
    response.headers["X-Total-Count"] = str(total)
    creds = q.offset(offset).limit(limit).all()
    # Secrets are never returned in the list — use GET /{cid}/secret to reveal
    return [_cred_schema_with_read_flag(c, False, db) for c in creds]


@router.post("", response_model=schemas.Cred, status_code=201)
def create_cred(
    body: schemas.CredCreate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, body.pid, user, "credentials.create")
    payload = body.model_dump()
    payload["domain"] = normalize_domain(payload.get("domain", ""))
    if payload.get("is_domain") and not payload["domain"]:
        username = payload.get("username", "") or ""
        if "@" in username:
            extracted = username.split("@", 1)[1]
            payload["domain"] = normalize_domain(extracted)
    if payload.get("secret"):
        payload["secret"] = encrypt_for_project(db, body.pid, payload["secret"])
    cred = models.Cred(id=new_id("c"), **payload)
    if payload.get("is_domain"):
        _validate_domain_host_links(
            payload["pid"], payload.get("domain", ""), payload.get("host_ids") or [], db
        )
    db.add(cred)
    label = f"Cred added: {cred.username}" + (f"@{cred.host}" if cred.host else "")
    log_event(
        db,
        cred.pid,
        getattr(request.state, "username", None),
        "cred",
        "create",
        label,
        {"username": cred.username},
    )
    mark_local_change(db, cred.pid, "cred", cred.id)
    db.commit()
    db.refresh(cred)
    bcast(cred.pid, "cred", "create", _cred_out(cred, user, db))
    return _cred_out(cred, user, db)


def _prep_cred_updates(body: "schemas.CredUpdate", cred: "models.Cred", db: Session) -> dict:
    updates = body.model_dump(exclude_none=True)
    if "domain" in updates:
        updates["domain"] = normalize_domain(updates.get("domain", ""))
    is_becoming_domain = updates.get("is_domain", False) and not cred.is_domain
    if is_becoming_domain and "domain" not in updates and not (cred.domain or "").strip():
        username = updates.get("username") or cred.username or ""
        if "@" in username:
            updates["domain"] = normalize_domain(username.split("@", 1)[1])
    if "secret" in updates and updates["secret"]:
        updates["secret"] = encrypt_for_project(db, cred.pid, updates["secret"])
    return updates


@router.patch("/{cid}", response_model=schemas.Cred)
def update_cred(
    cid: str,
    body: schemas.CredUpdate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    # Row lock: creds are frequently updated concurrently (e.g. automated
    # cred-reuse/cracking jobs marking cracked= alongside manual edits) — see
    # the same rationale on hosts.py::update_host (security audit finding F23).
    cred = db.query(models.Cred).filter(models.Cred.id == cid).with_for_update().first()
    if not cred:
        raise AppError("cred_not_found", "Credential not found", status=404)
    check_object_access(db, cred.pid, user, "credentials.update")
    old_cracked = cred.cracked
    updates = _prep_cred_updates(body, cred, db)
    for k, v in updates.items():
        setattr(cred, k, v)
    if cred.is_domain:
        _validate_domain_host_links(cred.pid, cred.domain or "", cred.host_ids or [], db)
    if body.cracked is not None and body.cracked and not old_cracked:
        log_event(
            db,
            cred.pid,
            getattr(request.state, "username", None),
            "cred",
            "cracked",
            f"Cred cracked: {cred.username}",
            {"username": cred.username},
        )
    mark_local_change(db, cred.pid, "cred", cred.id)
    db.commit()
    db.refresh(cred)
    bcast(cred.pid, "cred", "update", _cred_out(cred, user, db))
    return _cred_out(cred, user, db)


@router.delete("/{cid}", status_code=204)
def delete_cred(
    cid: str,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    cred = db.query(models.Cred).filter(models.Cred.id == cid).first()
    if not cred:
        raise AppError("cred_not_found", "Credential not found", status=404)
    check_object_access(db, cred.pid, user, "credentials.delete")
    pid = cred.pid
    log_event(
        db,
        pid,
        getattr(request.state, "username", None),
        "cred",
        "delete",
        f"Cred deleted: {cred.username}",
        {"username": cred.username},
    )
    db.delete(cred)
    db.commit()
    bcast(pid, "cred", "delete", {"id": cid})


@router.get("/{cid}/secret")
@limiter.limit("30/minute")
def reveal_secret(
    request: Request,
    cid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    cred = db.query(models.Cred).filter(models.Cred.id == cid).first()
    if not cred:
        raise AppError("cred_not_found", "Credential not found", status=404)
    check_pid_access(db, cred.pid, user, "credentials.read_secret")
    secret = decrypt_for_project(db, cred.pid, cred.secret)
    log_event(
        db,
        cred.pid,
        user.username,
        "audit",
        "secret_revealed",
        f"Secret revealed for {cred.username}",
        {"cred_id": cid, "username": cred.username},
    )
    db.commit()
    return {"secret": secret, "ttl": 30}
