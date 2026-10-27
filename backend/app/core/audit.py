"""Audit logging helper."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from ..models.audit import AuditEntry


def log_action(
    db: Session,
    *,
    action: str,
    actor_id: str | None = None,
    actor_name: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    project_id: str | None = None,
    org_id: str | None = None,
    detail: dict | str | None = None,
    ip_address: str | None = None,
) -> AuditEntry:
    """Create an immutable audit log entry.

    org_id is required for per-tier retention (ФТ-3,
    docs/modules/LICENSING_TZ.md) — most call sites don't pass it
    explicitly, so when it's omitted but project_id is given, it's
    resolved from Project.org_id here rather than requiring every
    project-scoped call site to look it up itself. Org-level call sites
    with no project_id (member/team actions) must still pass org_id
    explicitly.
    """
    if org_id is None and project_id:
        from ..models.project import Project

        project = db.query(Project).filter(Project.id == project_id).first()
        if project:
            org_id = project.org_id

    entry = AuditEntry(
        id=str(uuid.uuid4()),
        ts=datetime.now(UTC),
        actor_id=actor_id,
        actor_name=actor_name,
        action=action,
        target_type=target_type,
        target_id=target_id,
        project_id=project_id,
        org_id=org_id,
        detail=json.dumps(detail) if isinstance(detail, dict) else detail,
        ip_address=ip_address,
    )
    db.add(entry)
    return entry


ACT_LOGIN = "auth.login"
ACT_LOGOUT = "auth.logout"
ACT_TOKEN_REFRESH = "auth.token_refresh"
ACT_PASSWORD_CHANGE = "auth.password_change"
ACT_USER_CREATE = "user.create"
ACT_USER_UPDATE = "user.update"
ACT_USER_DELETE = "user.delete"
ACT_PROJECT_CREATE = "project.create"
ACT_PROJECT_UPDATE = "project.update"
ACT_PROJECT_DELETE = "project.delete"
ACT_MEMBER_ADD = "member.add"
ACT_MEMBER_REMOVE = "member.remove"
ACT_MEMBER_ROLE_CHANGE = "member.role_change"
ACT_HOST_CREATE = "host.create"
ACT_HOST_UPDATE = "host.update"
ACT_HOST_DELETE = "host.delete"
ACT_HOST_RESTORE = "host.restore"
ACT_FINDING_CREATE = "finding.create"
ACT_FINDING_UPDATE = "finding.update"
ACT_FINDING_DELETE = "finding.delete"
ACT_FINDING_RESTORE = "finding.restore"
ACT_NOTE_CREATE = "note.create"
ACT_NOTE_UPDATE = "note.update"
ACT_NOTE_DELETE = "note.delete"
ACT_LOOT_CREATE = "loot.create"
ACT_LOOT_DELETE = "loot.delete"
ACT_LOOT_RESTORE = "loot.restore"
ACT_CRED_CREATE = "cred.create"
ACT_CRED_DELETE = "cred.delete"
ACT_INFRA_CREATE = "infra.create"
ACT_INFRA_DEPLOY = "infra.deploy"
ACT_INFRA_DESTROY = "infra.destroy"
ACT_INFRA_DELETE = "infra.delete"
ACT_WS_CREATE = "workstation.create"
ACT_WS_START = "workstation.start"
ACT_WS_STOP = "workstation.stop"
ACT_WS_DELETE = "workstation.delete"
ACT_ATTACK_PATH_CREATE = "attack_path.create"
ACT_ATTACK_PATH_UPDATE = "attack_path.update"
ACT_ATTACK_PATH_DELETE = "attack_path.delete"
ACT_OIDC_PROVIDER_CREATE = "oidc_provider.create"
ACT_OIDC_PROVIDER_UPDATE = "oidc_provider.update"
ACT_OIDC_PROVIDER_DELETE = "oidc_provider.delete"
ACT_OIDC_LOGIN_SUCCESS = "oidc.login_success"
ACT_OIDC_LOGIN_FAILED = "oidc.login_failed"
ACT_OIDC_ACCOUNT_LINKED = "oidc.account_linked"
ACT_OIDC_JIT_PROVISIONED = "oidc.jit_provisioned"
ACT_EXPORT = "data.export"
ACT_IMPORT = "data.import"
ACT_SNAPSHOT_CREATE = "snapshot.create"
ACT_SNAPSHOT_APPLY = "snapshot.apply"
