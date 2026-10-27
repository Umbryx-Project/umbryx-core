"""
Per-tier audit trail retention (ФТ-3, docs/modules/LICENSING_TZ.md).

Runs daily per cluster (main.py's _audit_retention_loop, leader-election
role "audit_retention"). For every organization, resolves its effective
retention window via core/plan.get_org_plan() (works whether or not the
org has an OrganizationPlan row at all — Free-by-default orgs get the
Free window) and hard-deletes AuditEntry rows older than that window.

retention_days == -1 (Enterprise default, or any tier's license override)
means "custom / no automatic cleanup" — those orgs are skipped entirely;
MONETIZATION.md frames Enterprise retention as a contractual, per-customer
policy, not something to auto-delete against a guessed default.

Entries with org_id IS NULL (couldn't be attributed at write time — see
core/audit.py's resolution logic, or rows predating migration 096) are
left untouched: there's no tier to check them against, and deleting
unattributed forensic records by default would be the wrong failure mode
for an audit log.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from .. import models
from .logging_setup import get_logger
from .plan import get_org_plan

logger = get_logger(__name__)


def run_retention_pass(db: Session) -> dict:
    results: dict[str, int] = {}
    state = db.get(models.InstanceLicenseState, "instance")
    floor = state.retention_floor_days if state else None
    if floor == -1:
        return results
    org_ids = [row[0] for row in db.query(models.Organization.id).all()]
    for org_id in org_ids:
        plan = get_org_plan(org_id, db)
        retention_days = plan.get("retention_days", 30)
        if retention_days is None or retention_days < 0:
            continue
        retention_days = max(retention_days, floor or 0)
        cutoff = datetime.now(UTC) - timedelta(days=retention_days)
        deleted = (
            db.query(models.AuditEntry)
            .filter(
                models.AuditEntry.org_id == org_id,
                models.AuditEntry.ts < cutoff,
            )
            .delete(synchronize_session=False)
        )
        if deleted:
            db.commit()
            results["deleted_entries"] = results.get("deleted_entries", 0) + deleted
            results["orgs_cleaned"] = results.get("orgs_cleaned", 0) + 1
            logger.info(
                "[audit-retention] org %s: purged %d entries older than %d days",
                org_id,
                deleted,
                retention_days,
            )
    return results
