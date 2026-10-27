"""
Modules API — admin endpoints for module management and universal object CRUD.

Prefix: /api/modules
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models
from ..core.access import check_object_access
from ..core.deps import get_current_user, is_admin, require_admin
from ..core.events import log_event
from ..core.modules import (
    disable_module,
    enable_module,
    ext_registry,
    get_all_states,
    health_check,
    obj_type_registry,
)
from ..core.utils import new_id
from ..database import get_db
from ..models.core_object import CoreObject


def _authorize_object_read(db: Session, obj: CoreObject, user: models.User) -> None:
    """Enforce project membership to read a CoreObject.

    Objects with no project_id are platform-global (e.g. module examples that
    don't scope to a project) — reads of those stay open to any authenticated
    user, same as before this fix; project-scoped objects require membership.
    """
    if obj.project_id:
        check_object_access(db, obj.project_id, user)


def _authorize_object_write(db: Session, obj: CoreObject, user: models.User) -> None:
    """Enforce authz to create/update/delete a CoreObject.

    Project-scoped objects require project membership. Global objects
    (project_id=None) are restricted to admins, so a non-admin member of one
    project can't tamper with another module's shared global state.
    """
    if obj.project_id:
        check_object_access(db, obj.project_id, user)
    elif not is_admin(user):
        from ..core.errors import AppError

        raise AppError("insufficient_permissions", "Insufficient permissions", status=403)


def _has_object_access(db: Session, obj: CoreObject, user: models.User) -> bool:
    try:
        _authorize_object_read(db, obj, user)
        return True
    except Exception:
        return False


router = APIRouter(prefix="/api/modules", tags=["modules"])


# ── Module management ────────────────────────────────────────────────────


@router.get("")
def list_modules():
    """List all discovered modules with their state."""
    return {"modules": get_all_states()}


@router.post("/{module_id}/enable")
def api_enable_module(module_id: str, _admin: Annotated[Any, Depends(require_admin)]):
    ok, msg = enable_module(module_id)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "enabled", "module_id": module_id}


@router.post("/{module_id}/disable")
def api_disable_module(module_id: str, _admin: Annotated[Any, Depends(require_admin)]):
    ok, msg = disable_module(module_id)
    if not ok:
        raise HTTPException(status_code=400, detail=msg)
    return {"status": "disabled", "module_id": module_id}


@router.get("/{module_id}/health")
def api_health_check(module_id: str):
    return health_check(module_id)


# ── Object types catalog ─────────────────────────────────────────────────


@router.get("/object-types")
def list_object_types():
    """Return all registered object type schemas."""
    return {"types": obj_type_registry.all_types()}


@router.get("/object-types/{type_name}")
def get_object_type(type_name: str):
    schema = obj_type_registry.get(type_name)
    if schema is None:
        raise HTTPException(status_code=404, detail=f"Unknown object type '{type_name}'")
    mod = obj_type_registry.get_module(type_name)
    return {**schema.to_dict(), "module_id": mod}


# ── Extension points catalog ─────────────────────────────────────────────


@router.get("/extensions")
def list_extensions():
    """Return all registered extension point entries."""
    return {"extensions": ext_registry.all_points()}


@router.get("/extensions/{point}")
def get_extensions_for_point(point: str):
    """Return extension entries for a specific point."""
    return {"point": point, "entries": ext_registry.get_dicts(point)}


# ── Universal object CRUD ────────────────────────────────────────────────


class CreateObjectRequest(BaseModel):
    type: str
    name: str = ""
    project_id: str | None = None
    data: dict[str, Any] = {}
    status: str = "active"


class UpdateObjectRequest(BaseModel):
    name: str | None = None
    data: dict[str, Any] | None = None
    status: str | None = None


@router.get("/objects")
def list_objects(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[Any, Depends(get_current_user)],
    type: str | None = Query(None),
    project_id: str | None = Query(None),
    status: str | None = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
):
    """List core objects with optional filters, scoped to the caller's projects."""
    from sqlalchemy import or_

    from ..core.access import get_user_member_pids

    q = db.query(CoreObject)
    if project_id:
        check_object_access(db, project_id, user)
        q = q.filter(CoreObject.project_id == project_id)
    elif not is_admin(user):
        member_pids = get_user_member_pids(db, user)
        q = q.filter(or_(CoreObject.project_id.in_(member_pids), CoreObject.project_id.is_(None)))
    if type:
        q = q.filter(CoreObject.type == type)
    if status:
        q = q.filter(CoreObject.status == status)

    total = q.count()
    items = q.order_by(CoreObject.updated_at.desc()).offset(offset).limit(limit).all()
    return {"items": [o.to_dict() for o in items], "total": total}


@router.post("/objects")
def create_object(
    req: CreateObjectRequest,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[Any, Depends(get_current_user)],
):
    schema = obj_type_registry.get(req.type)
    if schema is None:
        raise HTTPException(status_code=400, detail=f"Unknown object type '{req.type}'")

    if req.project_id:
        check_object_access(db, req.project_id, user)
    elif not is_admin(user):
        from ..core.errors import AppError

        raise AppError("insufficient_permissions", "Insufficient permissions", status=403)

    module_id = obj_type_registry.get_module(req.type)

    # Validate data
    errors = obj_type_registry.validate_data(req.type, req.data)
    if errors:
        raise HTTPException(status_code=422, detail={"errors": errors})

    # Apply defaults
    data = dict(req.data)
    for field_def in schema.fields:
        if field_def.name not in data and field_def.default is not None:
            data[field_def.name] = field_def.default

    obj = CoreObject(
        id=new_id("obj"),
        type=req.type,
        module_id=module_id or "",
        project_id=req.project_id,
        name=req.name or data.get("name", data.get("title", "")),
        status=req.status,
        data=data,
        created_by=getattr(user, "id", None),
    )
    db.add(obj)
    db.commit()
    db.refresh(obj)
    if obj.project_id:
        log_event(
            db,
            obj.project_id,
            getattr(user, "username", None),
            "module_object",
            "create",
            f"Created {obj.type} object {obj.id}",
        )
    return obj.to_dict()


@router.get("/objects/{obj_id}")
def get_object(
    obj_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[Any, Depends(get_current_user)],
):
    obj = db.get(CoreObject, obj_id)
    if obj is None:
        raise HTTPException(status_code=404, detail="Object not found")
    _authorize_object_read(db, obj, user)
    return obj.to_dict()


@router.patch("/objects/{obj_id}")
def update_object(
    obj_id: str,
    req: UpdateObjectRequest,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[Any, Depends(get_current_user)],
):
    obj = db.get(CoreObject, obj_id)
    if obj is None:
        raise HTTPException(status_code=404, detail="Object not found")
    _authorize_object_write(db, obj, user)

    if req.data is not None:
        merged = {**obj.data, **req.data}
        errors = obj_type_registry.validate_data(obj.type, merged)
        if errors:
            raise HTTPException(status_code=422, detail={"errors": errors})
        obj.data = merged

    if req.name is not None:
        obj.name = req.name
    if req.status is not None:
        obj.status = req.status

    db.commit()
    db.refresh(obj)
    if obj.project_id:
        log_event(
            db,
            obj.project_id,
            getattr(user, "username", None),
            "module_object",
            "update",
            f"Updated {obj.type} object {obj.id}",
        )
    return obj.to_dict()


@router.delete("/objects/{obj_id}")
def delete_object(
    obj_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[Any, Depends(get_current_user)],
):
    obj = db.get(CoreObject, obj_id)
    if obj is None:
        raise HTTPException(status_code=404, detail="Object not found")
    _authorize_object_write(db, obj, user)
    pid, otype = obj.project_id, obj.type
    db.delete(obj)
    db.commit()
    if pid:
        log_event(
            db,
            pid,
            getattr(user, "username", None),
            "module_object",
            "delete",
            f"Deleted {otype} object {obj_id}",
        )
    return {"status": "deleted", "id": obj_id}


# ── Relations ────────────────────────────────────────────────────────────


class SetRelationRequest(BaseModel):
    relation_type: str
    target_id: str
    metadata: dict[str, Any] = {}


@router.post("/objects/{obj_id}/relations")
def add_relation(
    obj_id: str,
    req: SetRelationRequest,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[Any, Depends(get_current_user)],
):
    obj = db.get(CoreObject, obj_id)
    if obj is None:
        raise HTTPException(status_code=404, detail="Object not found")
    _authorize_object_write(db, obj, user)

    target = db.get(CoreObject, req.target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target object not found")
    _authorize_object_read(db, target, user)

    relations = dict(obj.relations or {})
    rel_list = relations.get(req.relation_type, [])
    rel_list.append({"id": req.target_id, **req.metadata})
    relations[req.relation_type] = rel_list
    obj.relations = relations

    db.commit()
    db.refresh(obj)
    return obj.to_dict()


@router.get("/objects/{obj_id}/relations/{relation_type}")
def get_relations(
    obj_id: str,
    relation_type: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[Any, Depends(get_current_user)],
):
    obj = db.get(CoreObject, obj_id)
    if obj is None:
        raise HTTPException(status_code=404, detail="Object not found")
    _authorize_object_read(db, obj, user)

    relations = obj.relations or {}
    rels = relations.get(relation_type, [])

    # Resolve target objects
    resolved = []
    for rel in rels:
        target = db.get(CoreObject, rel.get("id"))
        if target and _has_object_access(db, target, user):
            resolved.append({**rel, "object": target.to_dict()})
        else:
            resolved.append({**rel, "object": None})

    return {"relation_type": relation_type, "items": resolved}
