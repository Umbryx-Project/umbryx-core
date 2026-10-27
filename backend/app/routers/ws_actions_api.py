"""Workstation action logging — ingest, enable/disable, recent actions."""

from __future__ import annotations

import hmac
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import models
from ..core.deps import get_current_user, require_admin
from ..core.enums import UserRole
from ..core.workstation.actions import (
    ensure_token,
    extract_target_ips,
    ingest_action,
    install_hook,
    remove_hook,
)
from ..database import get_db

router = APIRouter(prefix="/api/workstations", tags=["workstation-actions"])


class ActionIngestBody(BaseModel):
    command: str = Field("", max_length=4000)
    user: str = Field("", max_length=120)
    cwd: str = Field("", max_length=500)
    ssh_client: str = Field("", max_length=120)
    tty: str = Field("", max_length=60)


@router.post("/ws-actions/{ws_id}")
def ws_action_ingest(
    ws_id: str,
    body: ActionIngestBody,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
):
    """Ingest endpoint for the workstation shell hook.

    Authenticated by the per-workstation bearer token (the workstation
    has no user cookies and must never get any) — the shell hook is the
    only caller.
    """
    auth = request.headers.get("authorization", "")
    token = auth.removeprefix("Bearer ").strip()
    ws = db.query(models.OperatorWorkstation).filter(models.OperatorWorkstation.id == ws_id).first()
    if not ws:
        raise HTTPException(404)
    meta = ws.meta if isinstance(ws.meta, dict) else {}
    expected = meta.get("action_log_token")
    if not expected or not token or not hmac.compare_digest(token.encode(), expected.encode()):
        raise HTTPException(401)
    if not meta.get("action_log_enabled"):
        raise HTTPException(403, "action logging disabled")

    action = ingest_action(db, ws, body.model_dump())
    return {"ok": True, "id": action.id}


@router.get("/actions-feed")
def actions_feed(
    db: Annotated[Session, Depends(get_db)],
    user=Depends(require_admin),
    limit: int = 100,
):
    """Cross-workstation operator command feed for Platform Ops → DevOps.

    Pull-mode machines are harvested over SSH on read (the hook only
    appends to a local file when the machine can't reach the platform)."""
    import time as _time

    from ..core.workstation.actions import pull_actions
    from ..models.workstation_action import WorkstationAction

    # pull enabled pull-mode machines (throttled to 10s per machine)
    now = _time.time()
    for ws in (
        db.query(models.OperatorWorkstation)
        .filter(models.OperatorWorkstation.is_pool.is_(True))
        .all()
    ):
        meta = ws.meta if isinstance(ws.meta, dict) else {}
        if meta.get("action_log_enabled") and meta.get("action_log_mode") == "pull":
            if now - float(meta.get("action_log_last_pull_ts") or 0) > 10:
                meta["action_log_last_pull_ts"] = now
                from sqlalchemy.orm.attributes import flag_modified

                flag_modified(ws, "meta")
                try:
                    pull_actions(db, ws)
                except Exception:  # noqa: BLE001 — feed must never 500
                    db.rollback()

    rows = (
        db.query(WorkstationAction)
        .order_by(WorkstationAction.ts.desc())
        .limit(min(limit, 500))
        .all()
    )
    ws_names = {
        w.id: w.name
        for w in db.query(models.OperatorWorkstation).filter(
            models.OperatorWorkstation.id.in_({r.workstation_id for r in rows})
        ).all()
    } if rows else {}
    return {
        "actions": [
            {
                "id": a.id,
                "workstation": ws_names.get(a.workstation_id, a.workstation_id),
                "username": a.username,
                "command": a.command,
                "cwd": a.cwd,
                "ssh_client": a.ssh_client,
                "tty": a.tty,
                "ts": a.ts,
            }
            for a in rows
        ]
    }


@router.post("/{ws_id}/action-log/enable")
def enable_action_log(
    ws_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    if user.role != UserRole.PLATFORM_ADMIN:
        raise HTTPException(403, "Platform admins only")
    ws = db.query(models.OperatorWorkstation).filter(models.OperatorWorkstation.id == ws_id).first()
    if not ws:
        raise HTTPException(404)
    token = ensure_token(db, ws)
    # Probe the callback URL FROM the machine: if it can POST back, use the
    # push hook. If it can't reach the platform at all (routed segment,
    # NAT), fall back to PULL mode — the hook appends to a local file and
    # the platform reads it over SSH (it only needs platform→machine,
    # which is the direction that always works for a managed machine).
    from ..core.workstation.actions import pick_callback_url

    url, unreachable = pick_callback_url(db, ws)
    mode = "push"
    if unreachable:
        mode = "pull"
        url = ""
    ok, message = install_hook(db, ws, url=url, token=token, mode=mode)
    if not ok:
        raise HTTPException(502, message)
    return {
        "ok": True,
        "message": f"{message} ({mode} mode)",
        "url": url or "pull://.umbryx/audit.log",
        "mode": mode,
        **({"warning": unreachable} if unreachable else {}),
    }


@router.post("/{ws_id}/action-log/disable")
def disable_action_log(
    ws_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    if user.role != UserRole.PLATFORM_ADMIN:
        raise HTTPException(403, "Platform admins only")
    ws = db.query(models.OperatorWorkstation).filter(models.OperatorWorkstation.id == ws_id).first()
    if not ws:
        raise HTTPException(404)
    ok, message = remove_hook(db, ws)
    if not ok:
        raise HTTPException(502, message)
    return {"ok": True, "message": message}


@router.get("/{ws_id}/actions")
def list_ws_actions(
    ws_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    limit: int = 100,
):
    from ..models.workstation_action import WorkstationAction

    ws = db.query(models.OperatorWorkstation).filter(models.OperatorWorkstation.id == ws_id).first()
    if not ws:
        raise HTTPException(404)
    if user.role != UserRole.PLATFORM_ADMIN and ws.user_id != user.id:
        _check_project_member(db, ws, user)
    rows = (
        db.query(WorkstationAction)
        .filter(WorkstationAction.workstation_id == ws_id)
        .order_by(WorkstationAction.ts.desc())
        .limit(min(limit, 500))
        .all()
    )
    from ..core.termtrack.redact import can_view_command_secrets, redact_command_secrets

    pid_for_gate = ws.project_id or ""
    raw = (user.role == UserRole.PLATFORM_ADMIN) or (
        pid_for_gate and can_view_command_secrets(db, user, pid_for_gate)
    )
    return {
        "actions": [
            {
                "id": a.id,
                "username": a.username,
                "command": a.command if raw else redact_command_secrets(a.command),
                "cwd": a.cwd,
                "ts": a.ts,
                "targets": sorted(extract_target_ips(a.command)),
            }
            for a in rows
        ]
    }


def _log_url(db):
    from ..core.workstation.actions import _platform_log_url

    return _platform_log_url(db)


def _check_project_member(db, ws, user) -> None:
    from ..core.access import check_pid_access

    if ws.project_id:
        check_pid_access(db, ws.project_id, user, "hosts.read")
    else:
        raise HTTPException(403)
