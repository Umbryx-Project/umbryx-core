from typing import Annotated, Any

from fastapi import Depends
from sqlalchemy.orm import Session

from ... import models
from ...core.deps import get_current_user
from ...core.permissions import PERM_HOSTS_READ
from ...database import get_db
from ._adaptix import _adaptix_live_agents
from ._integrations import (
    _classify_privilege,
    _load_integrations,
    _require_c2,
    _visible_integrations_for_pid,
    router,
)
from ._mythic import _mythic_live_agents
from ._sliver import _sliver_live_agents

_PRIV_RANK = {"system": 2, "admin": 1, "user": 0}
_PRIV_STATUS = {"system": "owned", "admin": "pwned", "user": "access"}
_PRIV_LABEL = {"system": "SYSTEM", "admin": "admin", "user": "user"}

_LIVE_CONNECTORS: dict[str, Any] = {
    "adaptix": _adaptix_live_agents,
    "sliver": _sliver_live_agents,
    "mythic": _mythic_live_agents,
}


def _c2_deduplicate_agents(agents: list) -> dict:
    best: dict[tuple, dict] = {}
    for a in agents:
        ip = (a.get("ip") or "").strip()
        if not ip:
            continue
        tier = _classify_privilege(a.get("username") or "")
        key = (ip, tier)
        prev = best.get(key)
        if prev is None:
            best[key] = a
        elif a.get("alive") and not prev.get("alive"):
            best[key] = a
        elif a.get("alive") == prev.get("alive"):
            if (a.get("last_seen") or "") > (prev.get("last_seen") or ""):
                best[key] = a
    return best


def _c2_format_session_entry(cfg: dict, ip: str, tier: str, a: dict, matched) -> dict:
    return {
        "integration_id": cfg["id"],
        "integration_name": cfg.get("name") or cfg["type"],
        "integration_type": cfg["type"],
        "ip": ip,
        "hostname": a.get("hostname") or "",
        "username": a.get("username") or "",
        "domain": a.get("domain") or "",
        "os": a.get("os") or "",
        "arch": a.get("arch") or "",
        "process": a.get("process") or "",
        "beacon_id": a.get("beacon_id") or "",
        "listener": a.get("listener") or "",
        "alive": a.get("alive", True),
        "mark": a.get("mark") or "",
        "last_seen": a.get("last_seen") or "",
        "privilege_tier": tier,
        "privilege_label": _PRIV_LABEL[tier],
        "suggested_status": _PRIV_STATUS[tier],
        "matched_host_id": matched.id if matched else None,
        "matched_host_status": matched.status if matched else None,
    }


@router.get(
    "/sessions/{pid}",
    responses={
        400: {"description": "Bad request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
        502: {"description": "Bad gateway"},
    },
)
async def get_live_sessions(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    _require_c2()
    from ...core.access import check_pid_access

    check_pid_access(db, pid, user, PERM_HOSTS_READ)

    integrations = _load_integrations(db)
    visible = _visible_integrations_for_pid(integrations, pid)

    project_hosts = db.query(models.Host).filter(models.Host.pid == pid).all()
    ip_to_host = {h.ip: h for h in project_hosts if h.ip}

    result = []
    for cfg in visible:
        live_fn = _LIVE_CONNECTORS.get(cfg["type"])
        if not live_fn:
            continue
        try:
            agents = await live_fn(cfg)
            best = _c2_deduplicate_agents(agents)
            for (ip, tier), a in sorted(
                best.items(), key=lambda x: (-_PRIV_RANK[x[0][1]], x[0][0])
            ):
                entry = _c2_format_session_entry(cfg, ip, tier, a, ip_to_host.get(ip))
                entry["stale"] = _is_session_stale(a, cfg)
                result.append(entry)
        except Exception as e:
            result.append(
                {
                    "integration_id": cfg["id"],
                    "integration_name": cfg.get("name") or cfg["type"],
                    "integration_type": cfg["type"],
                    "error": str(e),
                }
            )

    return result


_STALE_THRESHOLD_MINUTES = 30


def _is_session_stale(agent: dict, cfg: dict) -> bool:
    """Return True if the session's last checkin exceeds the staleness threshold."""
    if agent.get("alive") is False:
        return True
    last_seen = agent.get("last_seen") or ""
    if not last_seen:
        return False
    try:
        from datetime import UTC, datetime

        for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.strptime(last_seen, fmt).replace(tzinfo=UTC)
                age = (datetime.now(UTC) - dt).total_seconds() / 60
                return age > _STALE_THRESHOLD_MINUTES
            except ValueError:
                continue
    except Exception:
        pass
    return False


@router.get(
    "/sessions/{pid}/health",
    responses={
        400: {"description": "Bad request"},
        403: {"description": "Forbidden"},
        404: {"description": "Not found"},
    },
)
async def get_sessions_health(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    """Health summary across all C2 integrations for a project."""
    _require_c2()
    from ...core.access import check_pid_access

    check_pid_access(db, pid, user, PERM_HOSTS_READ)

    integrations = _load_integrations(db)
    visible = _visible_integrations_for_pid(integrations, pid)

    health_summary = []
    total_alive = 0
    total_dead = 0
    total_stale = 0

    for cfg in visible:
        live_fn = _LIVE_CONNECTORS.get(cfg["type"])
        if not live_fn:
            continue
        entry = {
            "integration_id": cfg["id"],
            "integration_name": cfg.get("name") or cfg["type"],
            "integration_type": cfg["type"],
            "total": 0,
            "alive": 0,
            "dead": 0,
            "stale": 0,
            "status": "ok",
            "error": None,
        }
        try:
            agents = await live_fn(cfg)
            best = _c2_deduplicate_agents(agents)
            entry["total"] = len(best)
            for (_ip, _tier), a in best.items():
                if a.get("alive", True):
                    entry["alive"] += 1
                    if _is_session_stale(a, cfg):
                        entry["stale"] += 1
                else:
                    entry["dead"] += 1
            total_alive += entry["alive"]
            total_dead += entry["dead"]
            total_stale += entry["stale"]
            if entry["dead"] > 0 and entry["alive"] == 0:
                entry["status"] = "critical"
            elif entry["stale"] > 0 or entry["dead"] > 0:
                entry["status"] = "warning"
        except Exception as e:
            entry["status"] = "error"
            entry["error"] = str(e)

        health_summary.append(entry)

    return {
        "integrations": health_summary,
        "totals": {
            "total": total_alive + total_dead,
            "alive": total_alive,
            "dead": total_dead,
            "stale": total_stale,
        },
        "has_issues": total_dead > 0 or total_stale > 0,
    }
