"""
IOC Tracker — backend routes.

Project-scoped CRUD for IOC objects via the universal object model, plus
aggregate endpoints for the dashboard widget.

Audit 2026-08-31, finding 4.1.5: every endpoint used to be project-blind —
any authenticated user could read, create, edit and delete IOCs of ALL
projects. The router is now mounted under /api/projects/{pid}/ext/ioc-tracker
and each endpoint enforces project membership (check_pid_access) plus a
project_id filter on every query.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.access import check_pid_access
from app.core.deps import get_current_user
from app.core.modules import obj_type_registry
from app.core.utils import new_id
from app.database import get_db
from app.models import User

FASTAPI_ROUTER = APIRouter(prefix="/api/projects/{pid}/ext/ioc-tracker", tags=["ioc-tracker"])

_OBJECT_TYPE = "ioc"


def _require_member(db: Session, pid: str, user: User) -> None:
    check_pid_access(db, pid, user)


def _scoped_query(db: Session, pid: str):
    from app.models.core_object import CoreObject

    return db.query(CoreObject).filter(
        CoreObject.type == _OBJECT_TYPE,
        CoreObject.project_id == pid,
    )


def _get_scoped(db: Session, pid: str, ioc_id: str):
    from app.models.core_object import CoreObject

    obj = db.get(CoreObject, ioc_id)
    if not obj or obj.type != _OBJECT_TYPE or obj.project_id != pid:
        return None
    return obj


class IOCBody(BaseModel):
    value: str
    ioc_type: str = "ip"
    severity: str = "medium"
    status: str = "active"
    context: str = ""
    source: str = ""
    host_id: str | None = None
    first_seen: str | None = None
    last_seen: str | None = None


def _data_text(key: str):
    """JSONB text accessor for a data column (works on PG; SQLite test
    conftest compiles JSONB down and these filters are exercised via the
    API tests on the real query path)."""
    from app.models.core_object import CoreObject

    return CoreObject.data[key].astext


@FASTAPI_ROUTER.get("/iocs")
def list_iocs(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
    q: str = Query("", description="Search value/type/context"),
    ioc_type: str | None = Query(None),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
):
    """List the project's IOCs with optional filters."""
    _require_member(db, pid, user)
    query = _scoped_query(db, pid)

    if ioc_type:
        query = query.filter(_data_text("ioc_type") == ioc_type)
    if severity:
        query = query.filter(_data_text("severity") == severity)
    if status:
        query = query.filter(_data_text("status") == status)
    if q:
        pattern = f"%{q}%"
        query = query.filter(
            _data_text("value").ilike(pattern) | _data_text("context").ilike(pattern)
        )

    total = query.count()
    items = query.order_by(_created_at_col().desc()).offset(offset).limit(limit).all()
    return {"items": [o.to_dict() for o in items], "total": total}


def _created_at_col():
    from app.models.core_object import CoreObject

    return CoreObject.created_at


@FASTAPI_ROUTER.post("/iocs")
def create_ioc(
    pid: str,
    body: IOCBody,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
):
    """Create a new IOC in this project."""
    _require_member(db, pid, user)
    from app.models.core_object import CoreObject

    schema = obj_type_registry.get(_OBJECT_TYPE)
    if schema is None:
        raise HTTPException(400, f"Object type '{_OBJECT_TYPE}' not registered")

    data = body.model_dump()
    errors = obj_type_registry.validate_data(_OBJECT_TYPE, data)
    if errors:
        raise HTTPException(422, {"errors": errors})

    now = datetime.now(timezone.utc).isoformat()
    if not data.get("first_seen"):
        data["first_seen"] = now
    data["last_seen"] = data.get("last_seen") or now

    obj = CoreObject(
        id=new_id("ioc"),
        type=_OBJECT_TYPE,
        module_id="ioc-tracker",
        project_id=pid,
        name=data["value"],
        status=data.get("status", "active"),
        data=data,
        created_by=user.id,
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    return obj.to_dict()


@FASTAPI_ROUTER.get("/iocs/{ioc_id}")
def get_ioc(
    pid: str,
    ioc_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
):
    _require_member(db, pid, user)
    obj = _get_scoped(db, pid, ioc_id)
    if not obj:
        raise HTTPException(404, "IOC not found")
    return obj.to_dict()


@FASTAPI_ROUTER.patch("/iocs/{ioc_id}")
def update_ioc(
    pid: str,
    ioc_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
    updates: dict = Body(...),
):
    _require_member(db, pid, user)
    obj = _get_scoped(db, pid, ioc_id)
    if not obj:
        raise HTTPException(404, "IOC not found")

    merged = {**obj.data, **updates}
    errors = obj_type_registry.validate_data(_OBJECT_TYPE, merged)
    if errors:
        raise HTTPException(422, {"errors": errors})

    obj.data = merged
    obj.name = merged.get("value", obj.name)
    obj.status = merged.get("status", obj.status)
    db.commit()
    db.refresh(obj)
    return obj.to_dict()


@FASTAPI_ROUTER.delete("/iocs/{ioc_id}")
def delete_ioc(
    pid: str,
    ioc_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
):
    _require_member(db, pid, user)
    obj = _get_scoped(db, pid, ioc_id)
    if not obj:
        raise HTTPException(404, "IOC not found")
    db.delete(obj)
    db.commit()
    return {"status": "deleted", "id": ioc_id}


@FASTAPI_ROUTER.get("/summary")
def ioc_summary(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[User, Depends(get_current_user)],
):
    """Aggregate stats for this project's dashboard widget."""
    _require_member(db, pid, user)
    base = _scoped_query(db, pid)

    total = base.count()

    by_severity: dict[str, int] = {}
    by_type: dict[str, int] = {}
    by_status: dict[str, int] = {}

    for obj in base.all():
        sev = obj.data.get("severity", "unknown")
        itype = obj.data.get("ioc_type", "unknown")
        stat = obj.data.get("status", "unknown")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_type[itype] = by_type.get(itype, 0) + 1
        by_status[stat] = by_status.get(stat, 0) + 1

    recent = base.order_by(_created_at_col().desc()).limit(10).all()

    return {
        "total": total,
        "by_severity": by_severity,
        "by_type": by_type,
        "by_status": by_status,
        "recent": [o.to_dict() for o in recent],
    }
