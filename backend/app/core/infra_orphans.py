"""Orphaned-stack tracking.

A stack is "orphaned" when it lost its project binding without its
infrastructure being destroyed — today that happens on project deletion
(see routers/projects.py::delete_project) and, silently, whenever a
project row disappears through a DB-level cascade that triggers the
ondelete="SET NULL" of infra_stacks.project_id (e.g. organization
deletion). Those stacks keep consuming provider resources while nothing
points at them.

The helper here stamps rows found in that inconsistent state
(mode="project" but project_id IS NULL) so the UI's orphaned filter and
the stacks API can surface them.
"""

from sqlalchemy.orm import Session

from ..models.infra_v2 import InfraStack
from .utils import ts_now


def notify_admins_orphaned_stack(db: Session, stack: InfraStack, source_pid: str | None) -> None:
    """In-app notification to every active platform admin about a stack
    whose infrastructure survived its project.

    An orphaned stack is silent running cost — the whole point of the
    tracking is that someone notices. The DevOps log entry is only seen
    by whoever goes looking; a notification goes to the people who can
    destroy or re-bind the stack.
    """
    try:
        from ..models import User
        from .enums import UserRole
        from .notify import push_notification

        admins = (
            db.query(User)
            .filter(User.role == UserRole.PLATFORM_ADMIN, User.active.is_(True))
            .all()
        )
        origin = f" (project {source_pid})" if source_pid else " (source project unknown)"
        for admin in admins:
            push_notification(
                db,
                user_id=admin.id,
                type="warning",
                title=f"Stack '{stack.name}' orphaned — infrastructure still running",
                body=(
                    f"The project this stack was bound to was deleted, but the stack's "
                    f"cloud resources were NOT destroyed{origin}. Review it in "
                    f"Platform Ops → Stacks (orphaned filter) and destroy or re-bind it."
                ),
                link="/infra",
            )
    except Exception as exc:  # pragma: no cover — notification is best-effort
        import logging

        logging.getLogger(__name__).warning(
            "orphaned-stack notification failed for stack %s: %s", stack.id, exc
        )


def stamp_orphaned_stacks(db: Session) -> int:
    """Mark silently-detached stacks as orphaned. Returns stamped count.

    Safe to call repeatedly: already-stamped rows (detached_at set) are
    skipped, so this works both as a startup sweep and an ad-hoc repair.
    """
    rows = (
        db.query(InfraStack)
        .filter(
            InfraStack.mode == "project",
            InfraStack.project_id.is_(None),
            InfraStack.detached_at.is_(None),
        )
        .all()
    )
    if not rows:
        return 0

    from .devops_log import log_event

    now = ts_now()
    for stack in rows:
        stack.mode = "standalone"
        stack.bound_at = None
        stack.bound_by = None
        stack.detached_at = now
        deployment_log = list(stack.deployment_log or [])
        deployment_log.append({"ts": now, "event": "orphaned_by_project_delete"})
        stack.deployment_log = deployment_log
        log_event(
            db,
            stack_id=stack.id,
            level="warn",
            category="lifecycle",
            message=(
                "Stack orphaned: project row deleted without stack teardown "
                "(detected by startup sweep)"
            ),
        )
        notify_admins_orphaned_stack(db, stack, source_pid=None)
    db.commit()
    return len(rows)
