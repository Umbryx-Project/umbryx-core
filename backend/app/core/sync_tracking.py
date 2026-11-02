"""Local-change tracking for instance-to-instance sync conflict detection.

`SyncState.local_version` is the counter `/api/sync/push` compares against
`remote_version` to decide whether an incoming event conflicts with an
un-synced local edit (see routers/sync_api.py). Nothing bumped it — a
purely local edit never touched `SyncState` at all, so the comparison was
permanently `0 > N` (always false) and conflicting concurrent edits just
silently overwrote each other (found testing a live 2-instance sync
deployment, 2026-09-07: instance B's local edit to a host was clobbered by
an incoming update from instance A with no ConflictRecord ever created).

Call `mark_local_change` from the create/update endpoint of every entity
type `sync_api.py` knows how to apply (`host`, `finding`, `note`, `loot`,
`cred` — see `_ENTITY_MODELS`) right before the commit. It only touches
rows that already exist — i.e. entities this instance has synced with at
least one peer before — so it costs nothing for the common case where sync
is never configured or a given entity has never been synced.
"""

from __future__ import annotations

import os

from sqlalchemy.orm import Session

from .. import models


def mark_local_change(db: Session, pid: str, entity_type: str, entity_id: str) -> None:
    if not os.environ.get("SYNC_SIGNING_KEY"):
        return
    rows = (
        db.query(models.SyncState)
        .filter(
            models.SyncState.pid == pid,
            models.SyncState.entity_type == entity_type,
            models.SyncState.entity_id == entity_id,
        )
        .all()
    )
    for row in rows:
        row.local_version = (row.local_version or 0) + 1
