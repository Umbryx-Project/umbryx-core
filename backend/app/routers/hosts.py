import ipaddress
import re
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models, schemas
from ..core.access import check_object_access, check_pid_access, get_user_member_pids
from ..core.audit import ACT_HOST_CREATE, ACT_HOST_DELETE, ACT_HOST_RESTORE, log_action
from ..core.deps import get_current_user, is_admin
from ..core.events import bcast, log_event
from ..core.network_data import sync_host_to_nodes
from ..core.permissions import PERM_HOSTS_DELETE
from ..core.sync_tracking import mark_local_change
from ..core.utils import new_id, normalize_domain, ts_now
from ..database import get_db

router = APIRouter(prefix="/api/hosts", tags=["hosts"])


@router.get(
    "",
    response_model=list[schemas.Host],
    responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}},
)
def list_hosts(
    response: Response,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    pid: str | None = None,
    limit: Annotated[int, Query(ge=1, le=2000)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    if pid:
        check_pid_access(db, pid, user, "hosts.read")
        q = db.query(models.Host).filter(models.Host.pid == pid)
    elif is_admin(user):
        q = db.query(models.Host)
    else:
        member_pids = get_user_member_pids(db, user)
        q = db.query(models.Host).filter(models.Host.pid.in_(member_pids))
    q = q.filter(models.Host.deleted_at.is_(None))
    total = q.count()
    response.headers["X-Total-Count"] = str(total)
    hosts = q.offset(offset).limit(limit).all()
    return [schemas.Host.model_validate(h) for h in hosts]


@router.post(
    "",
    response_model=schemas.Host,
    status_code=201,
    responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}},
)
def create_host(
    body: schemas.HostCreate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, body.pid, user, "hosts.create")
    payload = body.model_dump()
    payload["domain"] = normalize_domain(payload.get("domain", ""))
    payload["role"] = payload.get("role") or "unknown"
    payload["is_attacker"] = bool(payload.get("is_attacker")) or payload["role"] == "attacker"
    if payload["is_attacker"]:
        payload["status"] = "attacker"
    host = models.Host(id=new_id("hst"), **payload)
    db.add(host)
    label = f"Host added: {host.ip}" + (f" ({host.hostname})" if host.hostname else "")
    log_event(
        db,
        host.pid,
        getattr(request.state, "username", None),
        "host",
        "create",
        label,
        {"ip": host.ip},
    )
    log_action(
        db,
        action=ACT_HOST_CREATE,
        actor_id=getattr(request.state, "uid", None),
        actor_name=getattr(request.state, "username", None),
        target_type="host",
        target_id=host.id,
        project_id=host.pid,
        ip_address=request.client.host if request.client else None,
    )
    mark_local_change(db, host.pid, "host", host.id)
    db.commit()
    try:
        from ..core.notify import push_to_project_members

        push_to_project_members(
            db,
            pid=host.pid,
            type="info",
            title="New host added",
            body=f"{host.ip} ({host.hostname or 'unknown'})",
            link=f"/hosts?focusId={host.id}",
            exclude_uid=request.state.uid,
        )
    except Exception:
        pass
    db.refresh(host)
    h = schemas.Host.model_validate(host)
    bcast(host.pid, "host", "create", h.model_dump())
    return host


@router.patch(
    "/{hid}",
    response_model=schemas.Host,
    responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}},
)
def update_host(
    hid: str,
    body: schemas.HostUpdate,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    # Row lock: hosts are frequently updated concurrently by parallel scan
    # jobs writing discovered ports/services alongside manual operator edits
    # — without this, two concurrent PATCHes can each read the pre-update
    # row and the second commit silently loses fields the first one set that
    # this request's payload doesn't touch (security audit finding F23).
    host = db.query(models.Host).filter(models.Host.id == hid).with_for_update().first()
    if not host:
        raise HTTPException(404, "Host not found")
    check_object_access(db, host.pid, user, "hosts.update")
    old_status = host.status
    updates = body.model_dump(exclude_none=True)
    if "domain" in updates:
        updates["domain"] = normalize_domain(updates.get("domain", ""))
    if "role" in updates and updates["role"] == "attacker":
        updates["is_attacker"] = True
        updates["status"] = "attacker"
    if updates.get("is_attacker") is True:
        updates["role"] = "attacker"
        updates["status"] = "attacker"
    for k, v in updates.items():
        setattr(host, k, v)
    if body.status is not None and body.status != old_status:
        # Reversible event — Timeline UI surfaces an "Undo" button.
        log_event(
            db,
            host.pid,
            getattr(request.state, "username", None),
            "host",
            "status",
            f"Host {host.ip} status → {host.status}",
            {
                "ip": host.ip,
                "old": old_status,
                "new": host.status,
                "reversible": True,
                "undo": {
                    "entity": "host",
                    "id": host.id,
                    "type": "patch",
                    "patch": {"status": old_status},
                },
            },
        )
    ts = ts_now()
    node_payloads = sync_host_to_nodes(host, db, ts=ts)
    mark_local_change(db, host.pid, "host", host.id)
    db.commit()
    db.refresh(host)
    h = schemas.Host.model_validate(host)
    bcast(host.pid, "host", "update", h.model_dump())
    # Live-update mirrored network nodes (status badges, role icons, etc.)
    for payload in node_payloads:
        bcast(
            host.pid,
            "network",
            "node_updated",
            {"network_id": payload.pop("network_id", ""), "node": payload},
        )
    return host


@router.delete(
    "/{hid}",
    response_model=schemas.Host,
    responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}},
)
def delete_host(
    hid: str,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    host = db.query(models.Host).filter(models.Host.id == hid).first()
    if not host:
        raise HTTPException(404, "Host not found")
    check_object_access(db, host.pid, user, "hosts.delete")
    pid = host.pid
    log_event(
        db,
        pid,
        getattr(request.state, "username", None),
        "host",
        "delete",
        f"Host deleted: {host.ip}",
        {"ip": host.ip},
    )
    log_action(
        db,
        action=ACT_HOST_DELETE,
        actor_id=getattr(request.state, "uid", None),
        actor_name=getattr(request.state, "username", None),
        target_type="host",
        target_id=host.id,
        project_id=pid,
        ip_address=request.client.host if request.client else None,
    )
    host.deleted_at = ts_now()
    db.commit()
    bcast(pid, "host", "delete", {"id": hid})
    return host


@router.post(
    "/{hid}/restore",
    response_model=schemas.Host,
    responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}},
)
def restore_host(
    hid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    host = db.query(models.Host).filter(models.Host.id == hid).first()
    if not host:
        raise HTTPException(404, "Host not found")
    check_object_access(db, host.pid, user, PERM_HOSTS_DELETE)
    if host.deleted_at is None:
        raise HTTPException(400, "Host is not deleted")
    host.deleted_at = None
    log_action(
        db,
        action=ACT_HOST_RESTORE,
        actor_id=user.id,
        actor_name=user.username,
        target_type="host",
        target_id=host.id,
        project_id=host.pid,
    )
    db.commit()
    db.refresh(host)
    bcast(host.pid, "host", "update", schemas.Host.model_validate(host).model_dump())
    return host


class BulkHostImportBody(BaseModel):
    pid: str
    text: str
    tags: list[str] = []
    os: str = "Linux"
    status: str = "unknown"


def _try_add_plain_ip(token: str, ips: list, seen: set) -> None:
    try:
        ipaddress.ip_address(token)
        if token not in seen:
            seen.add(token)
            ips.append(token)
    except ValueError:
        pass


def _expand_ips(text: str) -> list[str]:
    ips: list[str] = []
    seen: set[str] = set()
    for token in re.split(r"[\s,;]+", text):
        token = token.strip()
        if not token:
            continue
        try:
            net = ipaddress.ip_network(token, strict=False)
            for addr in net.hosts():
                s = str(addr)
                if s not in seen:
                    seen.add(s)
                    ips.append(s)
        except ValueError:
            _try_add_plain_ip(token, ips, seen)
    return ips


@router.post(
    "/bulk",
    status_code=201,
    responses={400: {"description": "Bad request"}, 404: {"description": "Not found"}},
)
def bulk_import_hosts(
    body: BulkHostImportBody,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, body.pid, user, "hosts.create")
    ips = _expand_ips(body.text)
    if not ips:
        raise HTTPException(400, "No valid IPs or CIDR ranges found in input")

    existing_ips = {h.ip for h in db.query(models.Host).filter(models.Host.pid == body.pid).all()}
    username = getattr(request.state, "username", None)
    created = []
    skipped = 0

    ts_now()

    for ip in ips:
        if ip in existing_ips:
            skipped += 1
            continue
        host = models.Host(
            id=new_id("hst"),
            pid=body.pid,
            ip=ip,
            os=body.os,
            status=body.status,
            tags=body.tags,
        )
        db.add(host)
        existing_ips.add(ip)
        created.append(host)

    if created:
        log_event(
            db,
            body.pid,
            username,
            "host",
            "bulk_import",
            f"Bulk import: {len(created)} hosts added",
            {"count": len(created)},
        )
    db.commit()

    result = []
    for host in created:
        db.refresh(host)
        h = schemas.Host.model_validate(host)
        bcast(body.pid, "host", "create", h.model_dump())
        result.append(h.model_dump())

    return {"created": len(created), "skipped": skipped, "hosts": result}


@router.get("/{hid}/transport")
def get_host_transport(
    hid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    """Return session-aware transport advice for reaching this host."""
    host = db.query(models.Host).filter(models.Host.id == hid).first()
    if not host:
        raise HTTPException(404, "Host not found")
    check_pid_access(db, host.pid, user, "hosts.read")
    from ..core.session_transport import advise_transport

    advice = advise_transport(db, host.pid, host.ip or host.hostname or "")
    return advice.to_dict()


# ── Scan diff endpoints ────────────────────────────────────────────────


@router.get("/{hid}/scan-history")
def get_scan_history(
    hid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    limit: Annotated[int, Query(ge=1, le=100)] = 20,
):
    host = db.query(models.Host).filter(models.Host.id == hid).first()
    if not host:
        raise HTTPException(404, "Host not found")
    check_object_access(db, host.pid, user, "hosts.read")
    from ..core.scan_diff import get_host_scan_history

    snaps = get_host_scan_history(db, host.pid, host.id, limit)
    return [
        {
            "id": s.id,
            "job_id": s.job_id,
            "connector_key": s.connector_key,
            "created_at": s.created_at,
            "summary": {
                "ports": len(s.snapshot_json.get("ports", [])),
                "services": len(s.snapshot_json.get("services", [])),
                "findings": len(s.snapshot_json.get("findings", [])),
            },
        }
        for s in snaps
    ]


@router.get("/{hid}/scan-diff")
def get_scan_diff(
    hid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    old_id: str | None = None,
    new_id: str | None = None,
):
    host = db.query(models.Host).filter(models.Host.id == hid).first()
    if not host:
        raise HTTPException(404, "Host not found")
    check_object_access(db, host.pid, user, "hosts.read")
    from ..core.scan_diff import diff_snapshots

    if old_id and new_id:
        old = (
            db.query(models.ScanSnapshot)
            .filter(models.ScanSnapshot.id == old_id, models.ScanSnapshot.host_id == host.id)
            .first()
        )
        new = (
            db.query(models.ScanSnapshot)
            .filter(models.ScanSnapshot.id == new_id, models.ScanSnapshot.host_id == host.id)
            .first()
        )
        if not old or not new:
            raise HTTPException(404, "Snapshot not found")
        diff = diff_snapshots(old.snapshot_json, new.snapshot_json)
        diff["old_scan_at"] = old.created_at
        diff["new_scan_at"] = new.created_at
        diff["old_scan_type"] = old.connector_key
        diff["new_scan_type"] = new.connector_key
        return diff

    from ..core.scan_diff import get_latest_diff_for_host

    diff = get_latest_diff_for_host(db, host.pid, host.id)
    if diff is None:
        return {"has_changes": False, "message": "Not enough scan history for diffing"}
    return diff


# ── Risk score endpoints ───────────────────────────────────────────────


@router.get("/risk-scores")
def get_risk_scores(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    pid: str = "",
):
    if not pid:
        raise HTTPException(400, "pid is required")
    check_pid_access(db, pid, user, "hosts.read")
    from ..core.risk_score import compute_project_risk_scores

    return compute_project_risk_scores(db, pid)


@router.get("/{hid}/risk-score")
def get_host_risk_score(
    hid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    host = db.query(models.Host).filter(models.Host.id == hid).first()
    if not host:
        raise HTTPException(404, "Host not found")
    check_object_access(db, host.pid, user, "hosts.read")
    from ..core.risk_score import compute_host_risk

    return compute_host_risk(db, host)


# ── Burn / teardown endpoints ──────────────────────────────────────────


@router.post("/{hid}/burn")
def burn_host(
    hid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    """Mark a host as burned and return teardown checklist."""
    host = db.query(models.Host).filter(models.Host.id == hid).first()
    if not host:
        raise HTTPException(404, "Host not found")
    check_pid_access(db, host.pid, user, "hosts.update")
    from ..core.burn import burn_host as _burn

    return _burn(db, host, actor=user.username or "")


@router.get("/{hid}/burn-checklist")
def get_burn_checklist(
    hid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    """Get teardown checklist without marking host as burned."""
    host = db.query(models.Host).filter(models.Host.id == hid).first()
    if not host:
        raise HTTPException(404, "Host not found")
    check_object_access(db, host.pid, user, "hosts.read")
    from ..core.burn import _build_burn_checklist

    return _build_burn_checklist(db, host.pid, host.id)
