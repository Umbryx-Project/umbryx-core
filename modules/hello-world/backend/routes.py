"""
Hello World module — backend routes.

Exposes a custom endpoint that demonstrates how a module can add
its own API surface beyond the universal object model CRUD.

The FASTAPI_ROUTER attribute is discovered by the module loader.
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.core_object import CoreObject

router = APIRouter(prefix="/api/ext/hello-world", tags=["hello-world"])


@router.get("/stats")
def greeting_stats(
    project_id: str | None = Query(None),
    db: Session = Depends(get_db),
):
    """Aggregate statistics for greeting objects."""
    q = db.query(CoreObject).filter(CoreObject.type == "greeting")
    if project_id:
        q = q.filter(CoreObject.project_id == project_id)

    items = q.all()

    by_priority = {}
    for item in items:
        priority = (item.data or {}).get("priority", "unknown")
        by_priority[priority] = by_priority.get(priority, 0) + 1

    total_views = sum((item.data or {}).get("view_count", 0) for item in items)

    return {
        "total": len(items),
        "by_priority": by_priority,
        "total_views": total_views,
        "public_count": sum(
            1 for item in items if (item.data or {}).get("is_public", False)
        ),
    }


@router.post("/greetings/{obj_id}/view")
def increment_view(obj_id: str, db: Session = Depends(get_db)):
    """Increment view count for a greeting."""
    obj = db.get(CoreObject, obj_id)
    if obj is None:
        return {"error": "not found"}, 404

    data = dict(obj.data or {})
    data["view_count"] = data.get("view_count", 0) + 1
    obj.data = data
    db.commit()
    db.refresh(obj)
    return obj.to_dict()


FASTAPI_ROUTER = router
