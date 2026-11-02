"""
Structured system logging — platform-level events visible to DevOps.

Categories: system, security, operations, audit, infra, performance

Each call writes a `SystemLog` row AND emits to Python `logging`
so docker logs / Loki also get the event.

Usage:
    from app.core.system_log import log_system, log_security

    await log_system("platform.started", {"version": "0.3.0"})
    await log_security("auth.failed", user_id="u1", ip="1.2.3.4", success=False)
"""

import logging
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from .. import models
from .utils import new_id

logger = logging.getLogger("app.system")

_LOG_LEVELS = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}


def _now_ts() -> str:
    return datetime.now(UTC).isoformat()


def _write(
    db: Session,
    category: str,
    event: str,
    message: str,
    level: str = "info",
    user_id: str | None = None,
    project_id: str | None = None,
    request_id: str | None = None,
    ip: str | None = None,
    detail: dict | None = None,
) -> None:
    row = models.SystemLog(
        id=new_id("slog"),
        category=category,
        level=level,
        event=event,
        message=message,
        user_id=user_id,
        project_id=project_id,
        request_id=request_id,
        ip=ip,
        detail=detail or {},
        ts=_now_ts(),
    )
    try:
        db.add(row)
        db.commit()
    except Exception:
        db.rollback()
        logger.debug("system_log DB write failed for event=%s", event)

    py_level = _LOG_LEVELS.get(level, logging.INFO)
    logger.log(
        py_level,
        "[%s] %s — %s",
        category,
        event,
        message,
    )


def log_system(
    db: Session,
    event: str,
    detail: dict | None = None,
    message: str = "",
    level: str = "info",
) -> None:
    _write(db, "system", event, message or event, level=level, detail=detail)


def log_security(
    db: Session,
    event: str,
    user_id: str | None = None,
    ip: str | None = None,
    success: bool = True,
    detail: dict | None = None,
    message: str = "",
    level: str = "info",
) -> None:
    merged = {"success": success}
    if detail:
        merged.update(detail)
    _write(
        db,
        "security",
        event,
        message or event,
        level=level if success else "warning",
        user_id=user_id,
        ip=ip,
        detail=merged,
    )


def log_operations(
    db: Session,
    event: str,
    project_id: str | None = None,
    user_id: str | None = None,
    detail: dict | None = None,
    message: str = "",
    level: str = "info",
) -> None:
    _write(
        db,
        "operations",
        event,
        message or event,
        level=level,
        project_id=project_id,
        user_id=user_id,
        detail=detail,
    )


def log_infra(
    db: Session,
    event: str,
    instance_id: str | None = None,
    resource: str | None = None,
    status: str | None = None,
    detail: dict | None = None,
    message: str = "",
    level: str = "info",
) -> None:
    merged = {}
    if instance_id:
        merged["instance_id"] = instance_id
    if resource:
        merged["resource"] = resource
    if status:
        merged["status"] = status
    if detail:
        merged.update(detail)
    _write(db, "infra", event, message or event, level=level, detail=merged)


def log_performance(
    db: Session,
    endpoint: str,
    duration_ms: int,
    extra: dict | None = None,
) -> None:
    merged = {"endpoint": endpoint, "duration_ms": duration_ms}
    if extra:
        merged.update(extra)
    _write(
        db,
        "performance",
        "request.slow",
        f"{endpoint} {duration_ms}ms",
        level="warning" if duration_ms > 1000 else "info",
        detail=merged,
    )
