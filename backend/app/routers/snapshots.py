"""
Project snapshots — P8 checkpoint/rollback.

Snapshot captures a serialised copy of selected entity groups:
  notes     — all notes for the project
  findings  — all findings
  hosts     — host status/tags/role (not structural data like IPs)
  graph     — manual edges only (is_manual=True or manual_override=True)

Apply restores only the groups you select, and:
  - graph restore only touches manual edges; auto-inferred edges are left alone
  - host restore patches mutable fields (status/tags/role/notes) but does NOT
    delete or reposition hosts (graph node positions are preserved)
  - notes/findings restore replaces all rows for the project
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models
from ..core.access import check_pid_access
from ..core.deps import get_current_user
from ..core.events import bcast, log_event
from ..core.network_data import delete_edge, get_edges, upsert_edge
from ..core.utils import new_id, ts_now
from ..database import get_db

router = APIRouter(prefix="/api/projects/{pid}/snapshots", tags=["snapshots"])

_ALL_GROUPS = {"notes", "findings", "hosts", "graph"}


# ── Serialisers ───────────────────────────────────────────────────────


def _snap_notes(db: Session, pid: str) -> list:
    # NB: this previously referenced Note.category/is_confidential/created_at,
    # none of which exist on the Note model (phase/tags/starred/ts do) — it
    # would have raised AttributeError the first time a project with any
    # notes was snapshotted. Fixed in passing while wiring Note.host_id.
    rows = (
        db.query(models.Note).filter(models.Note.pid == pid, models.Note.deleted_at.is_(None)).all()
    )
    return [
        {
            "id": n.id,
            "title": n.title,
            "content": n.content,
            "phase": n.phase,
            "tags": n.tags or [],
            "starred": n.starred,
            "host_id": n.host_id,
            "ts": n.ts,
        }
        for n in rows
    ]


def _snap_findings(db: Session, pid: str) -> list:
    rows = db.query(models.Finding).filter(models.Finding.pid == pid).all()
    return [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "status": f.status,
            "description": f.description,
            "remediation": f.remediation,
            "host_ids": f.host_ids or [],
            "cve": f.cve,
            "cvss": f.cvss,
            "tags": f.tags or [],
        }
        for f in rows
    ]


def _snap_hosts(db: Session, pid: str) -> list:
    """Capture only mutable fields that make sense to restore."""
    rows = db.query(models.Host).filter(models.Host.pid == pid).all()
    return [
        {
            "id": h.id,
            "status": h.status,
            "role": h.role,
            "tags": h.tags or [],
            "hostname": h.hostname,
            "os": h.os,
        }
        for h in rows
    ]


def _snap_graph(db: Session, pid: str) -> list:
    network = db.query(models.Network).filter(models.Network.pid == pid).first()
    if not network:
        return []
    edges = get_edges(network.id, db)
    return [e for e in edges if e.get("is_manual") or e.get("manual_override")]


# ── Deserialisers (apply) ─────────────────────────────────────────────


def _apply_notes(db: Session, pid: str, data: list) -> int:
    db.query(models.Note).filter(models.Note.pid == pid).delete(synchronize_session=False)
    live_host_ids = {h.id for h in db.query(models.Host.id).filter(models.Host.pid == pid).all()}
    for n in data:
        host_id = n.get("host_id")
        db.add(
            models.Note(
                id=n.get("id") or new_id("n"),
                pid=pid,
                title=n.get("title") or "Untitled",
                content=n.get("content") or "",
                phase=n.get("phase") or "recon",
                tags=n.get("tags") or [],
                starred=bool(n.get("starred")),
                host_id=host_id if host_id in live_host_ids else None,
                ts=n.get("ts") or ts_now(),
            )
        )
    return len(data)


def _apply_findings(db: Session, pid: str, data: list) -> int:
    db.query(models.Finding).filter(models.Finding.pid == pid).delete(synchronize_session=False)
    for f in data:
        db.add(
            models.Finding(
                id=f.get("id") or new_id("fn"),
                pid=pid,
                title=f.get("title") or "",
                severity=f.get("severity") or "info",
                status=f.get("status") or "open",
                description=f.get("description") or "",
                remediation=f.get("remediation") or "",
                host_ids=f.get("host_ids") or [],
                cve=f.get("cve") or "",
                cvss=f.get("cvss"),
                tags=f.get("tags") or [],
            )
        )
    return len(data)


def _apply_hosts(db: Session, pid: str, data: list) -> int:
    hid_map = {h.id: h for h in db.query(models.Host).filter(models.Host.pid == pid).all()}
    patched = 0
    for snap in data:
        host = hid_map.get(snap.get("id") or "")
        if not host:
            continue
        host.status = snap.get("status") or host.status
        host.role = snap.get("role") or host.role
        host.tags = snap.get("tags") if snap.get("tags") is not None else host.tags
        host.hostname = snap.get("hostname") or host.hostname
        host.os = snap.get("os") or host.os
        patched += 1
    return patched


def _apply_graph(db: Session, pid: str, data: list) -> int:
    network = db.query(models.Network).filter(models.Network.pid == pid).first()
    if not network:
        return 0
    # Delete existing manual edges, replace with snapshot
    existing = get_edges(network.id, db)
    for e in existing:
        if e.get("is_manual") or e.get("manual_override"):
            delete_edge(e["id"], db)
    for e in data:
        upsert_edge(network.id, pid, {**e, "is_manual": True}, db)
    return len(data)


# ── Routes ────────────────────────────────────────────────────────────


@router.get("")
def list_snapshots(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "hosts.read")
    rows = (
        db.query(models.ProjectSnapshot)
        .filter(models.ProjectSnapshot.pid == pid)
        .order_by(models.ProjectSnapshot.created_at.desc())
        .limit(50)
        .all()
    )
    return [
        {
            "id": s.id,
            "label": s.label,
            "groups": s.groups,
            "created_by": s.created_by,
            "created_at": s.created_at,
        }
        for s in rows
    ]


@router.post("", status_code=201)
def create_snapshot(
    pid: str,
    body: dict,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "hosts.update")
    label = (body.get("label") or "").strip() or f"Snapshot {ts_now()[:16]}"
    groups = [g for g in (body.get("groups") or list(_ALL_GROUPS)) if g in _ALL_GROUPS]
    if not groups:
        raise HTTPException(400, "At least one group required")

    data: dict = {}
    if "notes" in groups:
        data["notes"] = _snap_notes(db, pid)
    if "findings" in groups:
        data["findings"] = _snap_findings(db, pid)
    if "hosts" in groups:
        data["hosts"] = _snap_hosts(db, pid)
    if "graph" in groups:
        data["graph"] = _snap_graph(db, pid)

    snap = models.ProjectSnapshot(
        id=new_id("snap"),
        pid=pid,
        label=label,
        groups=groups,
        data_json=data,
        created_by=user.username or "",
        created_at=ts_now(),
    )
    db.add(snap)
    log_event(
        db,
        pid,
        user.username,
        "snapshot",
        "create",
        f"Snapshot created: {label} ({', '.join(groups)})",
        {"snapshot_id": snap.id},
    )
    db.commit()
    db.refresh(snap)
    return {
        "id": snap.id,
        "label": snap.label,
        "groups": snap.groups,
        "created_by": snap.created_by,
        "created_at": snap.created_at,
    }


@router.delete("/{sid}", status_code=204)
def delete_snapshot(
    pid: str,
    sid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "hosts.update")
    snap = (
        db.query(models.ProjectSnapshot)
        .filter(
            models.ProjectSnapshot.id == sid,
            models.ProjectSnapshot.pid == pid,
        )
        .first()
    )
    if not snap:
        raise HTTPException(404)
    db.delete(snap)
    db.commit()


@router.post("/{sid}/apply")
def apply_snapshot(
    pid: str,
    sid: str,
    body: dict,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "hosts.update")
    snap = (
        db.query(models.ProjectSnapshot)
        .filter(
            models.ProjectSnapshot.id == sid,
            models.ProjectSnapshot.pid == pid,
        )
        .first()
    )
    if not snap:
        raise HTTPException(404, "Snapshot not found")

    apply_groups = [
        g
        for g in (body.get("groups") or snap.groups)
        if g in _ALL_GROUPS and g in (snap.groups or [])
    ]
    if not apply_groups:
        raise HTTPException(400, "No valid groups to apply")

    data = snap.data_json or {}
    results: dict = {}

    if "notes" in apply_groups and "notes" in data:
        results["notes"] = _apply_notes(db, pid, data["notes"])
        bcast(pid, "note", "bulk_replace", {"count": results["notes"]})

    if "findings" in apply_groups and "findings" in data:
        results["findings"] = _apply_findings(db, pid, data["findings"])
        bcast(pid, "finding", "bulk_replace", {"count": results["findings"]})

    if "hosts" in apply_groups and "hosts" in data:
        results["hosts"] = _apply_hosts(db, pid, data["hosts"])
        bcast(pid, "host", "bulk_patch", {"count": results["hosts"]})

    if "graph" in apply_groups and "graph" in data:
        results["graph"] = _apply_graph(db, pid, data["graph"])
        network = db.query(models.Network).filter(models.Network.pid == pid).first()
        if network:
            bcast(pid, "network", "edges_updated", {"source": "snapshot_apply"})

    log_event(
        db,
        pid,
        user.username,
        "snapshot",
        "apply",
        f"Snapshot applied: {snap.label} ({', '.join(apply_groups)})",
        {"snapshot_id": sid, "groups_applied": apply_groups, "counts": results},
    )
    db.commit()

    return {"ok": True, "snapshot_id": sid, "groups_applied": apply_groups, "counts": results}
