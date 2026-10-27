from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .. import models
from ..core.deps import get_current_user, is_admin, require_admin
from ..database import get_db

router = APIRouter(prefix="/api/marketplace", tags=["marketplace"])


@router.get("/templates")
async def marketplace_templates(
    db: Session = Depends(get_db),
    _user=Depends(get_current_user),
):
    from ..models.infra_v2 import ServiceTemplate

    rows = (
        db.query(ServiceTemplate)
        .filter(ServiceTemplate.is_builtin.is_(True))
        .order_by(ServiceTemplate.name)
        .all()
    )
    community = (
        db.query(ServiceTemplate)
        .filter(ServiceTemplate.is_builtin.is_(False))
        .order_by(ServiceTemplate.name)
        .all()
    )
    return {
        "builtin": [
            {
                "id": t.id,
                "name": t.name,
                "type": t.type,
                "image_ref": t.image_ref,
                "is_builtin": True,
            }
            for t in rows
        ],
        "community": [
            {
                "id": t.id,
                "name": t.name,
                "type": t.type,
                "image_ref": t.image_ref,
                "is_builtin": False,
            }
            for t in community
        ],
    }


@router.get("/plans")
async def marketplace_plans(
    db: Session = Depends(get_db),
    _user=Depends(get_current_user),
):
    from ..core.plan import TIER_LIMITS

    return {
        tier: {
            "max_members": limits["max_members"],
            "max_infra_instances": limits["max_infra_instances"],
            "max_workstations": limits["max_workstations"],
            "retention_days": limits["retention_days"],
            "features": [str(f) for f in limits["features"]],
        }
        for tier, limits in TIER_LIMITS.items()
    }


@router.get("/plans/{org_id}")
async def marketplace_org_plan(
    org_id: str,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    # Plan/limits data (member counts, tier) is org-internal — reading
    # another organization's plan by guessing its id had no membership
    # check at all (security audit finding F29).
    if not is_admin(user):
        is_member = (
            db.query(models.OrganizationMember)
            .filter(
                models.OrganizationMember.org_id == org_id,
                models.OrganizationMember.user_id == user.id,
            )
            .first()
        )
        if not is_member:
            raise HTTPException(404, "Organization not found")
    from ..core.plan import ensure_org_plan

    plan = ensure_org_plan(org_id, db)
    return {
        "id": plan.id,
        "org_id": plan.org_id,
        "tier": plan.tier,
        "max_members": plan.max_members,
        "max_infra_instances": plan.max_infra_instances,
        "max_workstations": plan.max_workstations,
        "retention_days": plan.retention_days,
        "features": plan.features if isinstance(plan.features, list) else [],
    }


@router.patch("/plans/{org_id}")
async def marketplace_update_plan(
    org_id: str,
    body: dict,
    db: Session = Depends(get_db),
    _admin=Depends(require_admin),
):
    from ..core.plan import TIER_LIMITS, ensure_org_plan
    from ..core.utils import ts_now

    plan = ensure_org_plan(org_id, db)
    tier = body.get("tier", plan.tier)
    if tier not in TIER_LIMITS:
        raise HTTPException(400, f"Unknown tier: {tier}")
    limits = TIER_LIMITS[tier]
    plan.tier = tier
    plan.max_members = limits["max_members"]
    plan.max_infra_instances = limits["max_infra_instances"]
    plan.max_workstations = limits["max_workstations"]
    plan.retention_days = limits["retention_days"]
    plan.features = [str(f) for f in limits["features"]]
    plan.updated_at = ts_now()
    db.commit()
    db.refresh(plan)
    return {
        "id": plan.id,
        "org_id": plan.org_id,
        "tier": plan.tier,
        "max_members": plan.max_members,
        "max_infra_instances": plan.max_infra_instances,
        "max_workstations": plan.max_workstations,
        "retention_days": plan.retention_days,
        "features": plan.features,
    }
