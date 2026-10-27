"""
Anti-tamper reconciliation (ФТ-8, docs/modules/LICENSING_TZ.md).

Runs hourly per cluster (main.py's _license_reconciliation_loop, guarded by
the "license_reconciliation" leader-election role). Licensing is per
self-hosted instance (see core/license.py's module docstring), so there is
exactly one thing to check the license itself against — the latest
LicenseToken — but OrganizationPlan is still a per-org cache row, and a
self-hosted admin with direct DB access could edit any individual org's
row (or several) by hand. This job:

1. If the instance has never been licensed at all (no LicenseToken row),
   does nothing — nothing to reconcile against, orgs are managed manually
   via PATCH /api/marketplace/plans/{org_id}.
2. Emits any due lifecycle notification (expiry warning / grace / wind-down)
   via core/license_state.notify_admins_if_needed. Expiry no longer
   downgrades to Free — the lifecycle holds the tier through wind-down until
   renewal (C1) and the request gate enforces what wind-down blocks.
3. Compares every Organization's OrganizationPlan row against
   what the instance's current entitlement actually grants
   (core/plan.get_instance_entitlement) and reverts + logs any that
   drifted — per org, since a hand-edit could target just one org's cached
   row even though the underlying license is instance-wide. No hard
   lock-out: the plan is simply put back to what the instance's own
   license allows (docs/modules/LICENSING_TZ.md's non-functional
   requirement against a kill-switch).
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from .. import models
from .license_state import notify_admins_if_needed
from .logging_setup import get_logger
from .plan import ensure_org_plan, get_instance_entitlement
from .system_log import log_security
from .utils import ts_now

logger = get_logger(__name__)


def _latest_token(db: Session) -> models.LicenseToken | None:
    return db.query(models.LicenseToken).order_by(models.LicenseToken.verified_at.desc()).first()


def _actual_entitlement(plan: models.OrganizationPlan) -> dict:
    return {
        "tier": plan.tier,
        "features": sorted(str(f) for f in (plan.features or [])),
        "max_members": plan.max_members,
        "max_infra_instances": plan.max_infra_instances,
        "max_workstations": plan.max_workstations,
        "retention_days": plan.retention_days,
    }


def reconcile_org(db: Session, plan: models.OrganizationPlan, entitlement: dict) -> str:
    """Returns "reverted" or "ok" — a plain string keeps this trivially
    assertable from tests without inspecting DB state for the (most
    common) "nothing changed" case."""
    expected = {**entitlement, "features": sorted(str(f) for f in entitlement["features"])}
    actual = _actual_entitlement(plan)
    if expected == actual:
        return "ok"

    plan.tier = expected["tier"]
    plan.features = list(expected["features"])
    plan.max_members = expected["max_members"]
    plan.max_infra_instances = expected["max_infra_instances"]
    plan.max_workstations = expected["max_workstations"]
    plan.retention_days = expected["retention_days"]
    plan.updated_at = ts_now()
    db.commit()
    log_security(
        db,
        "license.tamper_detected",
        success=False,
        detail={"org_id": plan.org_id, "found": actual, "reverted_to": expected},
        message=f"OrganizationPlan for org {plan.org_id} didn't match the instance license — reverted",
    )
    logger.warning(
        "[license-reconciliation] org %s plan drifted from the instance license, reverted: %s -> %s",
        plan.org_id,
        actual,
        expected,
    )
    return "reverted"


def run_reconciliation_pass(db: Session) -> dict:
    latest = _latest_token(db)
    if not latest:
        return {}

    # Lifecycle notifications (expiry warnings, grace, wind-down) — the
    # lifecycle no longer downgrades to Free on expiry (C1: wind-down holds
    # the tier until renewal; the request gate enforces what wind-down
    # blocks). Reconciliation's own job is now purely anti-tamper: keep each
    # org's cached plan matching the instance entitlement.
    notify_admins_if_needed(db)

    entitlement = get_instance_entitlement(db)
    results: dict[str, int] = {}
    for org in db.query(models.Organization).all():
        plan = ensure_org_plan(org.id, db)
        outcome = reconcile_org(db, plan, entitlement)
        results[outcome] = results.get(outcome, 0) + 1
    return results
