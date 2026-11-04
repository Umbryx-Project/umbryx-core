"""Notification creation helper."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.models.notification import Notification


def push_notification(
    db: Session,
    *,
    user_id: str,
    type: str = "info",
    title: str,
    body: str | None = None,
    link: str | None = None,
    project_id: str | None = None,
) -> Notification:
    n = Notification(
        id=str(uuid.uuid4()),
        user_id=user_id,
        ts=datetime.now(UTC),
        type=type,
        title=title,
        body=body,
        link=link,
        project_id=project_id,
    )
    db.add(n)
    return n


def push_to_project_members(
    db: Session,
    *,
    pid: str,
    type: str = "info",
    title: str,
    body: str | None = None,
    link: str | None = None,
    exclude_uid: str | None = None,
):
    # Was `from app.models import models` — app.models has no `models`
    # attribute, so this ImportError fired on EVERY call and the in-app
    # notifications from hosts.py/findings.py silently never landed
    # (found while wiring surface-watch, 2026-09-15).
    from app.models import ProjectMember

    members = db.query(ProjectMember).filter(ProjectMember.project_id == pid).all()
    for m in members:
        if exclude_uid and m.user_id == exclude_uid:
            continue
        push_notification(
            db,
            user_id=m.user_id,
            type=type,
            title=title,
            body=body,
            link=link,
            project_id=pid,
        )
