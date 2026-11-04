"""
DevOps logger — centralized activity logging for all infra operations.

Lives in core, not in the infra package, because it is a logger rather
than part of deploying anything: Community Edition writes to it from
project and workstation operations (docs/modules/EDITIONS.md).

Writes persistent DevOpsLogEntry records that can be queried independently
of stacks (global view) or filtered per stack/service/level/category.
"""

from __future__ import annotations

import uuid
from typing import Any

from .utils import ts_now


def _category_from_event(event: str) -> str:
    """Infer a category from the event string for backward compat."""
    e = event.lower()
    if any(k in e for k in ("deploy", "provision", "skip_unchanged")):
        return "deploy"
    if any(k in e for k in ("destroy", "tear")):
        return "destroy"
    if any(k in e for k in ("error", "fail")):
        return "error"
    if "rollback" in e:
        return "rollback"
    if "dns" in e:
        return "dns"
    if "vpn" in e:
        return "vpn"
    if "firewall" in e:
        return "firewall"
    if "stack_" in e:
        return "lifecycle"
    return "infra"


def _level_from_event(event: str) -> str:
    """Infer log level from the event string."""
    e = event.lower()
    if any(k in e for k in ("error", "fail", "rollback")):
        return "error"
    if "warn" in e:
        return "warn"
    return "info"


def log_event(
    db,
    *,
    stack_id: str | None = None,
    service_id: str | None = None,
    provider_id: str | None = None,
    level: str = "info",
    category: str = "infra",
    message: str,
    details: dict[str, Any] | None = None,
    actor: str | None = None,
):
    """Write a DevOpsLogEntry to the database."""
    from ..models.infra_v2 import DevOpsLogEntry

    entry = DevOpsLogEntry(
        id=str(uuid.uuid4()),
        stack_id=stack_id,
        service_id=service_id,
        provider_id=provider_id,
        level=level,
        category=category,
        message=message[:4000],
        details=details or {},
        actor=actor,
        created_at=ts_now(),
    )
    db.add(entry)
    db.flush()


def log_from_engine_event(db, stack_id: str, event: str, actor: str | None = None):
    """Translate an engine _log() event string into a DevOpsLogEntry.

    This is called from engine._log() to mirror stack deployment_log entries
    into the centralized DevOps log.
    """
    log_event(
        db,
        stack_id=stack_id,
        level=_level_from_event(event),
        category=_category_from_event(event),
        message=event,
        actor=actor,
    )


def log_step(
    db,
    *,
    stack_id: str,
    step_type: str,
    step_name: str,
    status: str,
    message: str = "",
    duration_ms: int | None = None,
    service_id: str | None = None,
    actor: str | None = None,
):
    """Log a deploy step completion to the DevOps log."""
    level = "error" if status == "error" else "info"
    details = {"step_type": step_type, "status": status}
    if duration_ms is not None:
        details["duration_ms"] = duration_ms

    log_event(
        db,
        stack_id=stack_id,
        service_id=service_id,
        level=level,
        category=step_type if step_type != "deploy" else "deploy",
        message=f"[{step_type}] {step_name}: {status}" + (f" — {message}" if message else ""),
        details=details,
        actor=actor,
    )
