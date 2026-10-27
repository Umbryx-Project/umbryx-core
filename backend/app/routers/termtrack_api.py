"""Termtrack API: terminal sessions, observations, PTY telemetry control.

Access follows the platform's project model: session/observation lists
are project-scoped (check_pid_access); PTY enable/harvest is
admin/operator on the workstation (same gates the action-log endpoints
use). Session detail carries the raw-ish PTY view — that is sensitive
terminal content, so it demands at least the project's operator role,
never viewer.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models
from ..core.access import check_pid_access
from ..core.deps import get_current_user
from ..core.enums import UserRole
from ..core.termtrack import (
    apply_observation,
    close_idle_sessions,
    harvest_pty,
    install_pty_recorder,
)
from ..core.termtrack.enrich import apply_pending_for_project
from ..core.termtrack.redact import can_view_command_secrets, redact_command_secrets
from ..core.utils import ts_now
from ..database import get_db
from ..models.observation import Observation
from ..models.workstation_session import WorkstationSession

router = APIRouter(tags=["termtrack"])


def _ws_or_404(db: Session, ws_id: str) -> models.OperatorWorkstation:
    ws = db.query(models.OperatorWorkstation).filter(models.OperatorWorkstation.id == ws_id).first()
    if not ws:
        raise HTTPException(404)
    return ws


def _pid_access(db, user, pid, need_write=False):
    """check_pid_access raises for non-members/no-permission; it returns
    None for platform admins (bypass) — that is a pass, not a fail."""
    permission = "hosts.create" if need_write else "hosts.read"
    return check_pid_access(db, pid, user, permission)


# ── sessions ──────────────────────────────────────────────────────────


@router.get("/api/projects/{pid}/workstation-sessions")
def list_sessions(
    pid: str,
    db: Annotated[Session, Depends(get_db)] = ...,
    user: Annotated[models.User, Depends(get_current_user)] = ...,
    state: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
):
    _pid_access(db, user, pid)
    close_idle_sessions(db)
    q = db.query(WorkstationSession).filter(WorkstationSession.pid == pid)
    if state:
        q = q.filter(WorkstationSession.state == state)
    rows = q.order_by(WorkstationSession.last_event_at.desc()).limit(limit).all()
    ws_by_id = {w.id: w for w in db.query(models.OperatorWorkstation).filter(
        models.OperatorWorkstation.id.in_({r.workstation_id for r in rows}))}
    out = []
    for s in rows:
        ws = ws_by_id.get(s.workstation_id)
        out.append({
            "id": s.id,
            "workstation_id": s.workstation_id,
            "workstation": ws.name if ws else "",
            "tty": s.tty,
            "username": s.username,
            "state": s.state,
            "started_at": s.started_at,
            "last_event_at": s.last_event_at,
            "ended_at": s.ended_at,
            "last_source": s.last_source,
            "path": s.path or [],
            "pty_bytes": int(s.pty_bytes or 0),
            # uncertainty surfaced, not hidden: unconfirmed hops are
            # marked as such in path[] — the UI renders them differently
            "uncertain_hops": sum(1 for h in (s.path or []) if not h.get("confirmed")),
        })
    return out


@router.get("/api/workstations/{ws_id}/sessions/{sid}")
def session_detail(
    ws_id: str,
    sid: str,
    db: Annotated[Session, Depends(get_db)] = ...,
    user: Annotated[models.User, Depends(get_current_user)] = ...,
):
    ws = _ws_or_404(db, ws_id)
    if not ws.project_id:
        raise HTTPException(404)
    _pid_access(db, user, ws.project_id)
    sess = (
        db.query(WorkstationSession)
        .filter(WorkstationSession.id == sid, WorkstationSession.workstation_id == ws_id)
        .first()
    )
    if not sess:
        raise HTTPException(404)
    from ..models.workstation_action import WorkstationAction

    actions = (
        db.query(WorkstationAction)
        .filter(WorkstationAction.session_id == sid)
        .order_by(WorkstationAction.ts.asc())
        .limit(500)
        .all()
    )
    observations = (
        db.query(Observation)
        .filter(Observation.session_id == sid)
        .order_by(Observation.observed_at.desc())
        .limit(200)
        .all()
    )
    raw = can_view_command_secrets(db, user, ws.project_id)
    return {
        **{k: getattr(sess, k) for k in (
            "id", "workstation_id", "pid", "tty", "username", "state",
            "started_at", "last_event_at", "ended_at", "path", "pty_bytes",
            "last_source")},
        "workstation": ws.name,
        "commands_redacted": not raw,
        "actions": [
            {"id": a.id,
             "command": a.command if raw else redact_command_secrets(a.command),
             "ts": a.ts, "source": a.source,
             "cwd": a.cwd, "exit_code": a.exit_code}
            for a in actions
        ],
        "observations": [_obs_out(o, raw_commands=raw) for o in observations],
    }


# ── observations ──────────────────────────────────────────────────────


def _obs_out(o: Observation, raw_commands: bool = True) -> dict:
    prov = dict(o.provenance or {})
    if not raw_commands and prov.get("command"):
        prov = {**prov, "command": redact_command_secrets(prov["command"])}
    return {
        "id": o.id,
        "kind": o.kind,
        "tool": o.tool,
        "data": o.data or {},
        "confidence": o.confidence,
        "status": o.status,
        "summary": o.summary,
        "observed_at": o.observed_at,
        "applied_at": o.applied_at,
        "target_host_id": o.target_host_id,
        "provenance": prov,
        "session_id": o.session_id,
        "action_id": o.action_id,
        "workstation_id": o.workstation_id,
    }


@router.get("/api/projects/{pid}/observations")
def list_observations(
    pid: str,
    db: Annotated[Session, Depends(get_db)] = ...,
    user: Annotated[models.User, Depends(get_current_user)] = ...,
    status: str | None = Query(None),
    kind: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
):
    _pid_access(db, user, pid)
    raw = can_view_command_secrets(db, user, pid)
    q = db.query(Observation).filter(Observation.pid == pid)
    if status:
        q = q.filter(Observation.status == status)
    if kind:
        q = q.filter(Observation.kind == kind)
    rows = q.order_by(Observation.observed_at.desc()).limit(limit).all()
    return [_obs_out(o, raw_commands=raw) for o in rows]


class ObsAction(BaseModel):
    pass


@router.post("/api/projects/{pid}/observations/{oid}/approve")
def approve_observation(
    pid: str,
    oid: str,
    db: Annotated[Session, Depends(get_db)] = ...,
    user: Annotated[models.User, Depends(get_current_user)] = ...,
):
    _pid_access(db, user, pid, need_write=True)
    obs = db.query(Observation).filter(Observation.id == oid, Observation.pid == pid).first()
    if not obs:
        raise HTTPException(404)
    if obs.status == "applied":
        return {"ok": True, "already": True}
    report = apply_observation(db, obs, auto=False)
    obs.provenance = {**(obs.provenance or {}), "approved_by": user.username, "approved_at": ts_now()}
    db.commit()
    from ..core.events import log_event

    log_event(db, pid, user.username, "observation", "approved",
              f"{obs.kind}: {obs.summary}", {"observation_id": obs.id})
    return {"ok": True, "report": report}


@router.post("/api/projects/{pid}/observations/{oid}/dismiss")
def dismiss_observation(
    pid: str,
    oid: str,
    db: Annotated[Session, Depends(get_db)] = ...,
    user: Annotated[models.User, Depends(get_current_user)] = ...,
):
    _pid_access(db, user, pid, need_write=True)
    obs = db.query(Observation).filter(Observation.id == oid, Observation.pid == pid).first()
    if not obs:
        raise HTTPException(404)
    obs.status = "dismissed"
    obs.provenance = {**(obs.provenance or {}), "dismissed_by": user.username, "dismissed_at": ts_now()}
    db.commit()
    return {"ok": True}


@router.post("/api/projects/{pid}/observations/apply-pending")
def apply_pending(
    pid: str,
    db: Annotated[Session, Depends(get_db)] = ...,
    user: Annotated[models.User, Depends(get_current_user)] = ...,
):
    _pid_access(db, user, pid, need_write=True)
    return apply_pending_for_project(db, pid)


# ── PTY telemetry control ─────────────────────────────────────────────


def _ws_admin(db, user, ws) -> None:
    if user.role == UserRole.PLATFORM_ADMIN.value:
        return
    if ws.project_id and user.id == ws.user_id:
        return
    if ws.project_id:
        try:
            check_pid_access(db, ws.project_id, user, "hosts.create")
            return
        except Exception:  # noqa: BLE001 — fall through to 403
            pass
    raise HTTPException(403)


@router.post("/api/workstations/{ws_id}/pty/enable")
def pty_enable(
    ws_id: str,
    db: Annotated[Session, Depends(get_db)] = ...,
    user: Annotated[models.User, Depends(get_current_user)] = ...,
):
    ws = _ws_or_404(db, ws_id)
    _ws_admin(db, user, ws)
    ok, reason = install_pty_recorder(db, ws)
    if not ok:
        raise HTTPException(502, f"recorder install failed: {reason}")
    from sqlalchemy.orm.attributes import flag_modified

    meta = dict(ws.meta or {})
    meta["pty_enabled"] = True
    ws.meta = meta
    flag_modified(ws, "meta")
    db.commit()
    return {"ok": True, "detail": reason}


@router.post("/api/workstations/{ws_id}/pty/disable")
def pty_disable(
    ws_id: str,
    db: Annotated[Session, Depends(get_db)] = ...,
    user: Annotated[models.User, Depends(get_current_user)] = ...,
):
    ws = _ws_or_404(db, ws_id)
    _ws_admin(db, user, ws)
    from ..core.termtrack.pty import TERM_BEGIN, TERM_END
    from ..workstation.actions import _exec_channel

    argv, reason = _exec_channel(db, ws)
    if not reason:
        script = (
            f"sed -i '/{TERM_BEGIN}/,/{TERM_END}/d' /etc/profile.d/umbryx-termtrack.sh 2>/dev/null; "
            "rm -f /etc/profile.d/umbryx-termtrack.sh; echo removed"
        )
        if argv == ["__ssh__"]:
            from ..ssh_exec import run_ssh_command
            from ..workstation.pool import _ssh_config_for

            cfg = _ssh_config_for(ws, db)
            if cfg:
                run_ssh_command(cfg, script, 20)
        else:
            import subprocess

            try:
                subprocess.run(argv + [script], capture_output=True, text=True, timeout=45)
            except Exception:  # noqa: BLE001
                pass
    from sqlalchemy.orm.attributes import flag_modified

    meta = dict(ws.meta or {})
    meta["pty_enabled"] = False
    ws.meta = meta
    flag_modified(ws, "meta")
    db.commit()
    return {"ok": True}


@router.post("/api/workstations/{ws_id}/pty/harvest")
def pty_harvest(
    ws_id: str,
    db: Annotated[Session, Depends(get_db)] = ...,
    user: Annotated[models.User, Depends(get_current_user)] = ...,
):
    ws = _ws_or_404(db, ws_id)
    _ws_admin(db, user, ws)
    meta = ws.meta if isinstance(ws.meta, dict) else {}
    if not meta.get("pty_enabled"):
        raise HTTPException(400, "PTY telemetry not enabled")
    stats = harvest_pty(db, ws)
    if ws.project_id:
        apply_pending_for_project(db, ws.project_id)
    return {"ok": True, **stats}


@router.get("/api/workstations/{ws_id}/telemetry")
def telemetry_status(
    ws_id: str,
    db: Annotated[Session, Depends(get_db)] = ...,
    user: Annotated[models.User, Depends(get_current_user)] = ...,
):
    ws = _ws_or_404(db, ws_id)
    _ws_admin(db, user, ws)
    meta = ws.meta if isinstance(ws.meta, dict) else {}
    sessions = (
        db.query(WorkstationSession)
        .filter(WorkstationSession.workstation_id == ws_id)
        .order_by(WorkstationSession.last_event_at.desc())
        .limit(10)
        .all()
    )
    return {
        "hook_enabled": bool(meta.get("action_log_enabled")),
        "hook_mode": meta.get("action_log_mode", ""),
        "pty_enabled": bool(meta.get("pty_enabled")),
        "pty_files": len(meta.get("pty_offsets") or {}),
        "sessions": [
            {"id": s.id, "tty": s.tty, "state": s.state, "username": s.username,
             "last_event_at": s.last_event_at, "last_source": s.last_source}
            for s in sessions
        ],
    }
