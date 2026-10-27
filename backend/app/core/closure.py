from __future__ import annotations

from sqlalchemy.orm import Session

from .. import models
from ..core.logging_setup import get_logger
from ..core.utils import new_id, ts_now
from ..sdk.events import PlatformEvent, event_bus


class _NoInfrastructureModule(Exception):
    """Community Edition: there is no provisioning engine to call.

    A private signal, not an error condition — see the use site in
    close_project's infrastructure-teardown block.
    """


logger = get_logger(__name__)

VALID_TRANSITIONS = {
    "active": {"closing"},
    "closing": {"closed"},
    "closed": {"archived"},
    "draft": {"active"},
}


def can_transition(current: str, target: str) -> bool:
    return target in VALID_TRANSITIONS.get(current, set())


async def close_project(project_id: str, closed_by: str, db: Session) -> models.DecommissionReport:
    project = db.query(models.Project).filter(models.Project.id == project_id).first()
    if not project:
        raise ValueError(f"Project {project_id} not found")

    if not can_transition(project.status, "closing"):
        raise ValueError(f"Cannot close project in status: {project.status}")

    report = models.DecommissionReport(
        id=new_id("dr"),
        project_id=project_id,
        closed_by=closed_by,
        closure_started_at=ts_now(),
        final_status="pending",
    )
    db.add(report)

    project.status = "closing"
    db.commit()

    warnings: list[str] = []
    infra_destroyed: list[dict] = []
    secrets_revoked: list[dict] = []
    members_deactivated: list[dict] = []

    running_jobs = (
        db.query(models.Job)
        .filter(
            models.Job.pid == project_id,
            models.Job.status.in_(["queued", "running"]),
        )
        .count()
    )
    if running_jobs > 0:
        warnings.append(f"{running_jobs} running/queued jobs at closure time")

    open_findings = (
        db.query(models.Finding)
        .filter(
            models.Finding.pid == project_id,
            models.Finding.status.in_(["open", "new"]),
        )
        .count()
    )
    if open_findings > 0:
        warnings.append(f"{open_findings} open findings at closure time")

    try:
        # Community Edition deploys no infrastructure, so there is nothing
        # to tear down and the provisioning engine is not in the build
        # (docs/modules/EDITIONS.md). Skipping is the correct outcome — the
        # broad `except` below would otherwise turn an expected absence into
        # "Infrastructure cleanup error: No module named ..." on every
        # decommission report.
        from ..core.editions import ee_import
        from ..models.infra_v2 import InfraStack

        infra = ee_import("infra")
        if infra is None:
            raise _NoInfrastructureModule
        ProvisioningEngine = infra.ProvisioningEngine

        stacks = (
            db.query(InfraStack)
            .filter(
                InfraStack.project_id == project_id,
                InfraStack.status.notin_(["destroyed", "tearing_down"]),
            )
            .all()
        )
        engine = ProvisioningEngine(db)
        for stk in stacks:
            try:
                engine.destroy_stack(stk.id)
                infra_destroyed.append(
                    {
                        "name": stk.name,
                        "status": "destroyed",
                        "stack_id": stk.id,
                    }
                )
            except Exception as e:
                warnings.append(f"Failed to destroy stack '{stk.name}': {e}")
                infra_destroyed.append(
                    {"name": stk.name, "status": "destroy_failed", "error": str(e)}
                )
    except _NoInfrastructureModule:
        pass
    except Exception as e:
        warnings.append(f"Infrastructure cleanup error: {e}")

    try:
        secrets = (
            db.query(models.ProjectSecret)
            .filter(
                models.ProjectSecret.project_id == project_id,
                models.ProjectSecret.revoked_at.is_(None),
            )
            .all()
        )
        now = ts_now()
        for secret in secrets:
            secret.revoked_at = now
            secrets_revoked.append(
                {
                    "name": secret.name,
                    "kind": secret.kind,
                    "revoked_at": now,
                }
            )
    except Exception as e:
        warnings.append(f"Secret revocation error: {e}")

    try:
        members = (
            db.query(models.ProjectMember)
            .filter(
                models.ProjectMember.project_id == project_id,
                models.ProjectMember.is_active.is_(True),
            )
            .all()
        )
        now = ts_now()
        for member in members:
            member.is_active = False
            members_deactivated.append(
                {
                    "user_id": member.user_id,
                    "role": member.role,
                    "deactivated_at": now,
                }
            )
    except Exception as e:
        warnings.append(f"Member deactivation error: {e}")

    report.infra_destroyed = infra_destroyed
    report.secrets_revoked = secrets_revoked
    report.members_deactivated = members_deactivated
    report.warnings = warnings

    final_status = "completed" if not warnings else "completed_with_warnings"
    report.final_status = final_status
    report.closure_completed_at = ts_now()

    project.status = "closed"
    project.closed_at = ts_now()
    db.commit()

    try:
        await event_bus.emit(
            PlatformEvent.PROJECT_CLOSED,
            {
                "project_id": project_id,
                "closed_by": closed_by,
                "final_status": final_status,
                "warnings_count": len(warnings),
            },
        )
    except Exception:
        pass

    logger.info(
        "Project %s closed by %s — status=%s, warnings=%d",
        project_id,
        closed_by,
        final_status,
        len(warnings),
    )
    return report


def archive_project(project_id: str, db: Session) -> models.Project:
    project = db.query(models.Project).filter(models.Project.id == project_id).first()
    if not project:
        raise ValueError(f"Project {project_id} not found")
    if not can_transition(project.status, "archived"):
        raise ValueError(f"Cannot archive project in status: {project.status}")
    project.status = "archived"
    project.archived_at = ts_now()
    db.commit()
    return project
