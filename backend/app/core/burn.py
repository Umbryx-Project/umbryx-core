"""
Host/project burn — OPSEC compromise response system.

When a host or infrastructure is detected by the blue team or OPSEC fails,
operators need to:
1. Mark affected assets as burned
2. Get a teardown checklist (C2 sessions, infra stacks, credentials, pivots)
3. Execute cleanup with one-click actions (each requiring confirmation)

This module generates the checklist and provides burn status tracking.
Actual teardown (infra destroy, C2 session kill) calls existing functions.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from .. import models
from .logging_setup import get_logger

logger = get_logger(__name__)


def burn_host(db: Session, host: models.Host, *, actor: str = "") -> dict[str, Any]:
    """Mark a host as burned and generate teardown checklist.

    Sets host status to 'compromised', adds 'burned' tag, and returns
    a checklist of items that need cleanup.
    """
    pid = host.pid
    host_id = host.id

    # Mark as burned
    host.status = "compromised"
    tags = list(host.tags or [])
    if "burned" not in tags:
        tags.append("burned")
        host.tags = tags
        from sqlalchemy.orm.attributes import flag_modified

        flag_modified(host, "tags")
    db.add(host)

    # Log burn event
    from .events import bcast, log_event

    log_event(
        db,
        pid,
        actor,
        "host",
        "burn",
        f"Host {host.ip or host.hostname} burned by {actor}",
        {"host_id": host_id, "ip": host.ip, "hostname": host.hostname},
    )
    db.commit()
    bcast(pid, "host", "burn", {"id": host_id})

    return _build_burn_checklist(db, pid, host_id)


def _build_burn_checklist(db: Session, pid: str, host_id: str) -> dict[str, Any]:
    """Build a teardown checklist for a burned host."""
    checklist: list[dict] = []
    host = db.query(models.Host).filter(models.Host.id == host_id).first()

    # 1. C2 sessions on this host
    from ..routers.c2._integrations import _load_integrations, _visible_integrations_for_pid
    from ..routers.c2._sessions import _LIVE_CONNECTORS

    integrations = _visible_integrations_for_pid(_load_integrations(db), pid)
    c2_sessions = []
    for cfg in integrations:
        try:
            sessions = _LIVE_CONNECTORS.get_connector(cfg.get("id", ""), db, pid).list_sessions()
            for s in sessions:
                if s.get("host_id") == host_id or (host and s.get("host_ip") == host.ip):
                    c2_sessions.append(
                        {
                            "integration_id": cfg.get("id"),
                            "integration_name": cfg.get("name"),
                            "integration_type": cfg.get("type"),
                            "agent_id": s.get("agent_id"),
                            "agent_info": s.get("agent_info", ""),
                            "status": s.get("status", "unknown"),
                        }
                    )
        except Exception:
            pass

    if c2_sessions:
        checklist.append(
            {
                "id": "kill_c2_sessions",
                "label": f"Kill {len(c2_sessions)} C2 session(s)",
                "severity": "critical",
                "items": c2_sessions,
                "action": "kill_session",
            }
        )

    # 2. Active pivots through this host
    try:
        pivots = (
            db.query(models.PivotObservation)
            .filter(getattr(models.PivotObservation, "host_id", None) == host_id)
            .all()
            if hasattr(models, "PivotObservation") and hasattr(models.PivotObservation, "host_id")
            else []
        )
    except Exception:
        pivots = []
    if pivots:
        checklist.append(
            {
                "id": "close_pivots",
                "label": f"Close {len(pivots)} active pivot(s)",
                "severity": "high",
                "items": [
                    {"id": p.id, "type": getattr(p, "pivot_type", "unknown")} for p in pivots
                ],
                "action": "close_pivot",
            }
        )

    # 3. Credentials used on this host (may need rotation)
    try:
        cred_notes = (
            db.query(models.CredHostNote).filter(models.CredHostNote.host_id == host_id).all()
        )
        cred_ids = {n.cred_id for n in cred_notes}
        creds = db.query(models.Cred).filter(models.Cred.id.in_(cred_ids)).all() if cred_ids else []
    except Exception:
        creds = []
    if creds:
        checklist.append(
            {
                "id": "rotate_creds",
                "label": f"Rotate {len(creds)} credential(s) used on this host",
                "severity": "high",
                "items": [{"id": c.id, "username": c.username, "domain": c.domain} for c in creds],
                "action": "rotate_cred",
            }
        )

    # 4. Infra stacks associated with this project
    try:
        stacks = (
            db.query(models.InfraStack)
            .filter(
                getattr(models.InfraStack, "pid", None) == pid,
                models.InfraStack.status.notin_(["destroyed", "rolled_back"]),
            )
            .all()
            if hasattr(models, "InfraStack") and hasattr(models.InfraStack, "pid")
            else []
        )
    except Exception:
        stacks = []
    if stacks:
        checklist.append(
            {
                "id": "review_infra",
                "label": f"Review {len(stacks)} active infrastructure stack(s)",
                "severity": "medium",
                "items": [{"id": s.id, "name": s.name, "status": s.status} for s in stacks],
                "action": "destroy_stack",
            }
        )

    # 5. Loot collected from this host (may need to purge from blue team scope)
    try:
        loots = (
            db.query(models.Loot).filter(getattr(models.Loot, "host_id", None) == host_id).all()
            if hasattr(models, "Loot") and hasattr(models.Loot, "host_id")
            else []
        )
    except Exception:
        loots = []
    if loots:
        checklist.append(
            {
                "id": "review_loot",
                "label": f"Review {len(loots)} loot item(s) from this host",
                "severity": "low",
                "items": [
                    {"id": loot.id, "title": loot.title, "type": loot.type} for loot in loots
                ],
                "action": "review_loot",
            }
        )

    return {
        "host_id": host_id,
        "checklist": checklist,
        "total_items": sum(len(c.get("items", [])) for c in checklist),
        "critical_count": sum(1 for c in checklist if c["severity"] == "critical"),
    }
