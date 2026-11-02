"""
Reading the DevOps log.

The log itself has always been core: `core/devops_log.py` is a logger rather
than part of deploying anything, and Community writes to it from project and
workstation operations (`routers/projects.py:193`,
`routers/workstations.py:1037`, `core/infra_orphans.py:81`). The *read* was
left behind in the Enterprise infra router, so a Community instance filled
this table and had no way to look at it — the entries accumulated unseen.

Moving the read here is what makes the log mean the same thing in both
editions. Nothing about it is Enterprise: the rows a Community instance
writes describe its own projects and its own machines.

The path is /api/devops-log rather than the old /api/infra-v2/devops-log,
because /infra-v2 is the Enterprise deployment namespace and this is not part
of it.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from .. import models
from ..core.deps import get_current_user, is_admin
from ..database import get_db
from ..models.infra_v2 import DevOpsLogEntry

router = APIRouter(prefix="/api/devops-log", tags=["devops-log"])


def _admin(user):
    if not is_admin(user):
        raise HTTPException(403, "Platform admin required")


@router.get("")
def get_devops_log(
    db: Annotated[Session, Depends(get_db)] = ...,
    user: Annotated[models.User, Depends(get_current_user)] = ...,
    stack_id: str | None = Query(None),
    service_id: str | None = Query(None),
    level: str | None = Query(None),
    category: str | None = Query(None),
    limit: int = Query(200, le=1000),
    offset: int = Query(0),
):
    _admin(user)

    q = db.query(DevOpsLogEntry)
    if stack_id:
        q = q.filter(DevOpsLogEntry.stack_id == stack_id)
    if service_id:
        q = q.filter(DevOpsLogEntry.service_id == service_id)
    if level:
        q = q.filter(DevOpsLogEntry.level == level)
    if category:
        q = q.filter(DevOpsLogEntry.category == category)
    total = q.count()
    entries = q.order_by(DevOpsLogEntry.created_at.desc()).offset(offset).limit(limit).all()
    return {
        "total": total,
        "entries": [
            {
                "id": e.id,
                "stack_id": e.stack_id,
                "service_id": e.service_id,
                "provider_id": e.provider_id,
                "level": e.level,
                "category": e.category,
                "message": e.message,
                "details": e.details,
                "actor": e.actor,
                "created_at": e.created_at,
            }
            for e in entries
        ],
    }


@router.delete("")
def clear_devops_log(
    db: Annotated[Session, Depends(get_db)] = ...,
    user: Annotated[models.User, Depends(get_current_user)] = ...,
):
    """Always refuses. Kept so the answer is a stated rule, not a 404."""
    _admin(user)
    raise HTTPException(403, "DevOps log is immutable — entries cannot be deleted or modified")
