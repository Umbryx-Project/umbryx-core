"""
System logs API — DevOps / platform_admin access only.

GET /api/system/logs           — query system_logs table
GET /api/system/health         — platform health summary
GET /api/system/ha             — HA cluster status (pg_auto_failover + Redis Sentinel)
GET /api/system/edition        — build edition + license entitlement (any user)
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from .. import models
from ..core.deps import get_current_user, require_admin
from ..database import get_db

router = APIRouter(
    prefix="/api/system",
    tags=["system"],
    responses={403: {"description": "Forbidden"}},
)


class SystemLogOut(BaseModel):
    id: str
    category: str
    level: str
    event: str
    message: str
    user_id: str | None
    project_id: str | None
    request_id: str | None
    ip: str | None
    detail: dict
    ts: str


@router.get("/logs", response_model=list[SystemLogOut])
def query_system_logs(
    _admin: Annotated[models.User, Depends(require_admin)],
    db: Annotated[Session, Depends(get_db)],
    category: Annotated[str | None, Query(description="Filter by category")] = None,
    level: Annotated[str | None, Query(description="Filter by level")] = None,
    event: Annotated[str | None, Query(description="Filter by event prefix")] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
):
    q = db.query(models.SystemLog)
    if category:
        q = q.filter(models.SystemLog.category == category)
    if level:
        q = q.filter(models.SystemLog.level == level)
    if event:
        q = q.filter(models.SystemLog.event.startswith(event))
    q = q.order_by(models.SystemLog.ts.desc())
    return q.offset(offset).limit(limit).all()


@router.get("/logs/count")
def count_system_logs(
    _admin: Annotated[models.User, Depends(require_admin)],
    db: Annotated[Session, Depends(get_db)],
    category: str | None = None,
):
    q = db.query(func.count(models.SystemLog.id))
    if category:
        q = q.filter(models.SystemLog.category == category)
    return {"count": q.scalar()}


@router.get("/health")
def system_health(
    _admin: Annotated[models.User, Depends(require_admin)],
    db: Annotated[Session, Depends(get_db)],
):
    from ..core.worker_pool import get_pool

    pool = get_pool()
    user_count = db.query(models.User).filter(models.User.active).count()
    project_count = db.query(models.Project).count()

    return {
        "status": "ok",
        "worker": {
            "running": pool._running,
            "active_jobs": len(pool._active_job_ids),
            "max_workers": pool._max_workers,
            "max_per_project": pool._max_per_project,
        },
        "db": {
            "users": user_count,
            "projects": project_count,
        },
    }


@router.get("/ha")
def ha_status(
    _admin: Annotated[models.User, Depends(require_admin)],
):
    """HA cluster status — pg_auto_failover node states + Redis Sentinel.

    Read-only against whichever node/master currently holds write
    authority; safe to call regardless of who's primary right now.
    `enabled: false` (both `postgres`/`redis` null) on a regular
    single-node deployment — this isn't an error, HA_MONITOR_HOST and
    REDIS_SENTINEL_HOSTS are both opt-in.
    """
    from ..core.ha_status import get_ha_status

    return get_ha_status()


@router.get("/edition")
def system_edition(
    user: Annotated[models.User, Depends(get_current_user)],
    db: Annotated[Session, Depends(get_db)],
):
    """What this installation is and what it is entitled to.

    Readable by any authenticated user, not just admins: the frontend
    decides what to put in the navigation from this, and that decision has
    to be the same for every operator.

    Two separate facts, which the UI treats differently
    (docs/modules/EDITIONS.md):

    - ``edition`` is the build. In "ce" the Enterprise capabilities are not
      present at all and their endpoints 404, so the UI hides them rather
      than offering an upgrade prompt on a dead button.
    - ``tier`` / ``features`` are the license. In "ee" without a valid
      license the capability exists but answers 402 on mutating requests,
      which is worth an upsell.
    """
    from ..core.editions import edition
    from ..core.plan import get_instance_entitlement
    from ..core.version import PLATFORM_VERSION

    entitlement = get_instance_entitlement(db)
    return {
        "version": PLATFORM_VERSION,
        "edition": edition(),
        "tier": entitlement["tier"],
        "features": [str(f) for f in entitlement["features"]],
        "limits": {
            "max_members": entitlement["max_members"],
            "max_infra_instances": entitlement["max_infra_instances"],
            "max_workstations": entitlement["max_workstations"],
            "retention_days": entitlement["retention_days"],
        },
    }
