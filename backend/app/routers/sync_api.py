"""
Instance-to-instance sync — push/pull event log with conflict resolution.

Endpoints require admin + sync.manage permission.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import models
from ..core.access import check_pid_access
from ..core.deps import get_current_user
from ..core.events import log_event
from ..core.permissions import PERM_SYNC_MANAGE
from ..core.system_log import log_operations
from ..core.utils import new_id, ts_now
from ..database import get_db

router = APIRouter(prefix="/api/sync", tags=["sync"])

_SYNC_SIGNING_KEY = os.environ.get("SYNC_SIGNING_KEY", "")

# Entity types the sync engine can write back to. Kept as a module-level
# map so conflict resolution (below) and push ingestion (_apply_entity)
# agree on the exact same set.
_ENTITY_MODELS = {
    "host": lambda: models.Host,
    "finding": lambda: models.Finding,
    "note": lambda: models.Note,
    "loot": lambda: models.Loot,
    "cred": lambda: models.Cred,
}


def _apply_entity(db, pid, entity_type, entity_id, op, data):
    model_cls = _ENTITY_MODELS.get(entity_type, lambda: None)()
    if model_cls is None:
        return

    # Security audit 2026-10-09 (LOW): resolve the entity by (id, pid) — the
    # envelope signature binds the event to this pid, so an id collision with
    # another project must never be mutated from here (defense in depth on
    # top of the signed envelope).
    existing = db.query(model_cls).filter(model_cls.id == entity_id, model_cls.pid == pid).first()

    if op == "create":
        if existing:
            return
        if not data or not isinstance(data, dict):
            return
        obj = model_cls(id=entity_id, pid=pid, **data)
        db.add(obj)
    elif op == "update":
        if not existing:
            return
        if not data or not isinstance(data, dict):
            return
        for k, v in data.items():
            setattr(existing, k, v)
    elif op == "delete":
        if not existing:
            return
        if hasattr(existing, "deleted_at"):
            existing.deleted_at = ts_now()
        else:
            db.delete(existing)


def event_envelope(
    pid: str,
    instance_id: str,
    seq: int,
    entity_type: str,
    entity_id: str,
    op: str,
    payload_str: str,
) -> str:
    """Canonical string covered by the event signature.

    Security audit 2026-10-07 (finding 4): the HMAC used to cover ONLY the
    payload JSON, while op/entity_id/pid/instance_id/seq traveled unsigned —
    a captured, validly-signed event could be re-targeted (op flipped to
    "delete", another entity_id or another pid) and its seq-based
    anti-replay reset by claiming a fresh instance_id. The signature now
    binds the full envelope; /pull re-signs from the stored row so a
    signature pulled for one project cannot be re-pushed for another.
    """
    return json.dumps(
        {
            "pid": pid or "",
            "instance_id": instance_id or "",
            "seq": int(seq or 0),
            "entity_type": entity_type or "",
            "entity_id": entity_id or "",
            "op": op or "",
            "payload": payload_str,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def sign_event(envelope: str) -> str:
    if not _SYNC_SIGNING_KEY:
        return ""
    return (
        "sha256="
        + hmac.new(_SYNC_SIGNING_KEY.encode(), envelope.encode(), hashlib.sha256).hexdigest()
    )


def verify_event_signature(envelope: str, signature: str) -> bool:
    if not _SYNC_SIGNING_KEY:
        return False
    if not signature:
        return False
    expected = sign_event(envelope)
    return hmac.compare_digest(expected, signature)


def _require_sync_manage(db: Session, pid: str, user: models.User):
    check_pid_access(db, pid, user, PERM_SYNC_MANAGE)


@router.post("/push")
async def sync_push(
    body: dict,
    db: Annotated[Session, Depends(get_db)],
    user: models.User = Depends(get_current_user),
):
    pid = body.get("pid", "")
    _require_sync_manage(db, pid, user)

    if not _SYNC_SIGNING_KEY:
        raise HTTPException(403, "Sync is not configured (SYNC_SIGNING_KEY not set)")

    events = body.get("events", [])
    if not events:
        return {"applied": 0, "conflicts": 0}

    applied = 0
    conflicts = 0
    _batch_seq: dict[str, int] = {}

    for ev in events:
        instance_id = ev.get("instance_id", "")
        seq = ev.get("seq", 0)
        entity_type = ev.get("entity_type", "")
        entity_id = ev.get("entity_id", "")
        op = ev.get("op", "")
        payload_str = json.dumps(ev.get("payload", {}), sort_keys=True)
        payload_hash = ev.get("payload_hash", "")
        signature = ev.get("signature", "")

        if not instance_id or not entity_type or not entity_id or not op:
            continue

        envelope = event_envelope(
            pid, instance_id, seq, entity_type, entity_id, op, payload_str
        )
        if not verify_event_signature(envelope, signature):
            log_operations(
                db,
                "sync.push.rejected",
                project_id=pid,
                user_id=user.id,
                detail={"reason": "bad_signature", "instance_id": instance_id, "seq": seq},
            )
            continue

        if payload_hash:
            actual_hash = hashlib.sha256(payload_str.encode()).hexdigest()
            if actual_hash != payload_hash:
                log_operations(
                    db,
                    "sync.push.rejected",
                    project_id=pid,
                    user_id=user.id,
                    detail={"reason": "hash_mismatch", "instance_id": instance_id, "seq": seq},
                )
                continue

        last_event = (
            db.query(models.SyncEvent)
            .filter(models.SyncEvent.instance_id == instance_id)
            .order_by(models.SyncEvent.seq.desc())
            .first()
        )
        db_last_seq = last_event.seq if last_event else 0
        if not last_event:
            existing_state = (
                db.query(models.SyncState)
                .filter(models.SyncState.instance_id == instance_id)
                .order_by(models.SyncState.remote_version.desc())
                .first()
            )
            if existing_state and existing_state.remote_version > db_last_seq:
                db_last_seq = existing_state.remote_version
        last_seq = _batch_seq.get(instance_id, db_last_seq)
        if seq != last_seq + 1:
            log_operations(
                db,
                "sync.push.replay_rejected",
                project_id=pid,
                user_id=user.id,
                detail={"instance_id": instance_id, "seq": seq, "last_seq": last_seq},
            )
            continue

        sync_state = (
            db.query(models.SyncState)
            .filter(
                models.SyncState.instance_id == instance_id,
                models.SyncState.entity_type == entity_type,
                models.SyncState.entity_id == entity_id,
            )
            .first()
        )

        # local_version counts local edits (mark_local_change) made since
        # the last time THIS peer's push was successfully applied — reset
        # to 0 below whenever that happens. Comparing it against
        # remote_version (a peer's own incrementing seq number, unrelated
        # scale — already >0 after the very first successful sync) meant
        # this could never actually fire once any syncing had happened;
        # a bare "any local edit pending" check is what "conflict" means
        # here (found testing a live 2-instance deployment, 2026-09-07).
        if sync_state and (sync_state.local_version or 0) > 0:
            conflict = models.ConflictRecord(
                id=new_id("cfl"),
                entity_type=entity_type,
                entity_id=entity_id,
                local_payload={"version": sync_state.local_version},
                remote_payload=ev.get("payload", {}),
                detected_at=ts_now(),
                pid=pid,
            )
            db.add(conflict)
            conflicts += 1
            log_operations(
                db,
                "sync.push.conflict",
                project_id=pid,
                detail={"entity_type": entity_type, "entity_id": entity_id},
            )
        else:
            event_rec = models.SyncEvent(
                id=new_id("sev"),
                seq=seq,
                instance_id=instance_id,
                entity_type=entity_type,
                entity_id=entity_id,
                op=op,
                pid=pid,
                payload_hash=payload_hash or hashlib.sha256(payload_str.encode()).hexdigest(),
                signature=signature,
                ts=ts_now(),
                payload=ev.get("payload", {}),
            )
            db.add(event_rec)

            try:
                _apply_entity(
                    db, pid, entity_type, entity_id, op, ev.get("payload", {}).get("data")
                )
            except Exception:
                pass

            if not sync_state:
                sync_state = models.SyncState(
                    id=new_id("ss"),
                    instance_id=instance_id,
                    entity_type=entity_type,
                    entity_id=entity_id,
                    local_version=0,
                    remote_version=seq,
                    last_synced_at=ts_now(),
                    status="in_sync",
                    origin_instance=instance_id,
                    pid=pid,
                )
                db.add(sync_state)
            else:
                sync_state.remote_version = seq
                sync_state.last_synced_at = ts_now()
                sync_state.status = "in_sync"
                # A remote event just applied cleanly against no pending
                # local edit — clear the counter so it starts fresh for
                # whatever local edits happen next.
                sync_state.local_version = 0

            applied += 1
            _batch_seq[instance_id] = seq

    db.commit()

    log_event(
        db, pid, user.username, "sync", "push", f"Applied {applied} events, {conflicts} conflicts"
    )
    log_operations(
        db,
        "sync.push",
        project_id=pid,
        user_id=user.id,
        detail={"applied": applied, "conflicts": conflicts},
    )

    return {"applied": applied, "conflicts": conflicts}


@router.get("/pull")
async def sync_pull(
    instance_id: str,
    since_seq: int,
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: models.User = Depends(get_current_user),
):
    _require_sync_manage(db, pid, user)

    if not _SYNC_SIGNING_KEY:
        raise HTTPException(403, "Sync is not configured (SYNC_SIGNING_KEY not set)")

    events = (
        db.query(models.SyncEvent)
        .filter(
            models.SyncEvent.instance_id == instance_id,
            models.SyncEvent.seq > since_seq,
            models.SyncEvent.pid == pid,
        )
        .order_by(models.SyncEvent.seq.asc())
        .all()
    )

    return {
        "instance_id": instance_id,
        "pid": pid,
        "events": [
            {
                "id": e.id,
                "seq": e.seq,
                "instance_id": e.instance_id,
                "entity_type": e.entity_type,
                "entity_id": e.entity_id,
                "op": e.op,
                "payload_hash": e.payload_hash,
                # Re-signed over the full envelope of the stored row: the
                # signature a peer receives is bound to THIS project (e.pid),
                # the entity, the op and the seq — see event_envelope().
                "signature": sign_event(
                    event_envelope(
                        e.pid or pid,
                        e.instance_id,
                        e.seq,
                        e.entity_type,
                        e.entity_id,
                        e.op,
                        json.dumps(e.payload or {}, sort_keys=True),
                    )
                ),
                "ts": e.ts,
            }
            for e in events
        ],
    }


@router.get("/status")
async def sync_status(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: models.User = Depends(get_current_user),
):
    _require_sync_manage(db, pid, user)

    if not _SYNC_SIGNING_KEY:
        raise HTTPException(403, "Sync is not configured (SYNC_SIGNING_KEY not set)")

    states = db.query(models.SyncState).filter(models.SyncState.pid == pid).all()
    conflicts = (
        db.query(models.ConflictRecord)
        .filter(
            models.ConflictRecord.resolution == "pending",
            # Security audit 2026-10-09 (LOW): was a global count — a sync
            # manager of one project saw other projects' pending conflicts.
            models.ConflictRecord.pid == pid,
        )
        .count()
    )

    return {
        "pid": pid,
        "instances": [
            {
                "id": s.id,
                "instance_id": s.instance_id,
                "entity_type": s.entity_type,
                "entity_id": s.entity_id,
                "local_version": s.local_version,
                "remote_version": s.remote_version,
                "last_synced_at": s.last_synced_at,
                "status": s.status,
                "origin_instance": s.origin_instance,
            }
            for s in states
        ],
        "pending_conflicts": conflicts,
    }


def _apply_resolution_payload(db, pid, entity_type, entity_id, data) -> str:
    """Apply a conflict-resolution payload to the target entity.

    Returns "updated" or "created". Raises ValueError with a human-readable
    reason when the payload cannot be applied — conflict resolution must
    never *claim* success while leaving the data untouched (audit
    2026-08-31, finding 2.3.2/4.1.4).
    """
    model_cls = _ENTITY_MODELS.get(entity_type, lambda: None)()
    if model_cls is None:
        raise ValueError(f"Unsupported entity_type for conflict resolution: {entity_type!r}")
    if not data or not isinstance(data, dict):
        raise ValueError("Winning payload is empty or not an object — nothing to apply")

    existing = db.query(model_cls).filter(model_cls.id == entity_id, model_cls.pid == pid).first()
    try:
        if existing is not None:
            for k, v in data.items():
                setattr(existing, k, v)
            return "updated"
        obj = model_cls(id=entity_id, pid=pid, **data)
        db.add(obj)
        # Flush inside the try so NOT NULL / constraint violations surface
        # here as a 400 with a reason, not as a 500 after commit.
        db.flush()
        return "created"
    except TypeError as exc:
        raise ValueError(f"Payload fields don't fit {entity_type}: {exc}") from exc
    except IntegrityError as exc:
        raise ValueError(
            f"Winning payload doesn't satisfy {entity_type} constraints "
            f"(missing required fields?): {exc.orig}"
        ) from exc


@router.post("/conflicts/{conflict_id}/resolve")
async def resolve_conflict(
    conflict_id: str,
    body: dict,
    db: Annotated[Session, Depends(get_db)],
    user: models.User = Depends(get_current_user),
):
    pid = body.get("pid", "")
    _require_sync_manage(db, pid, user)

    if not _SYNC_SIGNING_KEY:
        raise HTTPException(403, "Sync is not configured (SYNC_SIGNING_KEY not set)")

    conflict = (
        db.query(models.ConflictRecord).filter(models.ConflictRecord.id == conflict_id).first()
    )
    if not conflict:
        raise HTTPException(status_code=404, detail="Conflict not found")
    if conflict.pid and conflict.pid != pid:
        # The conflict belongs to another project — don't resolve (or touch
        # entities) cross-project from this call.
        raise HTTPException(status_code=404, detail="Conflict not found")

    resolution = body.get("resolution", "")
    if resolution not in ("local_wins", "remote_wins", "manual"):
        raise HTTPException(status_code=400, detail="Invalid resolution")

    if conflict.resolution != "pending":
        raise HTTPException(status_code=400, detail="Conflict is already resolved")

    # Audit 2026-08-31, finding 2.3.2/4.1.4: the winning payload used to be
    # computed and dropped on the floor (an F841-suppressed dead variable) —
    # the endpoint reported success while the entity kept whatever data it
    # already had.
    # Now every resolution path applies its decision to the entity in the
    # SAME transaction as the conflict/status bookkeeping:
    #   - local_wins: local data is already canonical, nothing to write —
    #     but the sync state must acknowledge the local version so the same
    #     remote event doesn't re-conflict on the next push;
    #   - remote_wins: apply the remote payload captured at detection time
    #     ({"data": {...}} event shape, or the payload itself if it carries
    #     fields directly);
    #   - manual: apply the operator-supplied payload verbatim.
    applied = None
    if resolution == "local_wins":
        pass  # local data unchanged by design
    elif resolution == "remote_wins":
        payload = conflict.remote_payload or {}
        data = payload.get("data") if isinstance(payload.get("data"), dict) else payload
        try:
            applied = _apply_resolution_payload(
                db, pid, conflict.entity_type, conflict.entity_id, data
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    else:  # manual
        data = body.get("manual_payload", {})
        try:
            applied = _apply_resolution_payload(
                db, pid, conflict.entity_type, conflict.entity_id, data
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    conflict.resolution = resolution
    conflict.resolved_by = user.id
    conflict.resolved_at = ts_now()

    sync_state = (
        db.query(models.SyncState)
        .filter(
            models.SyncState.entity_type == conflict.entity_type,
            models.SyncState.entity_id == conflict.entity_id,
        )
        .first()
    )
    if sync_state:
        sync_state.status = "in_sync"
        sync_state.last_synced_at = ts_now()
        if resolution == "local_wins":
            # The local version won: treat it as acknowledged remotely so
            # the same change doesn't re-conflict on the next push.
            sync_state.remote_version = max(
                sync_state.remote_version or 0, sync_state.local_version or 0
            )

    # Entity write + conflict bookkeeping commit atomically — no window
    # where the conflict is "resolved" but the data wasn't updated.
    db.commit()

    log_event(
        db,
        pid,
        user.username,
        "sync",
        "conflict_resolved",
        f"Conflict {conflict_id} resolved as {resolution}",
    )
    log_operations(
        db,
        "sync.conflict_resolved",
        project_id=pid,
        user_id=user.id,
        detail={"conflict_id": conflict_id, "resolution": resolution},
    )

    return {
        "id": conflict.id,
        "resolution": conflict.resolution,
        "resolved_at": conflict.resolved_at,
        # What actually happened to the data: "updated"/"created" for
        # remote_wins/manual, "local_unchanged" for local_wins.
        "applied": applied if applied is not None else "local_unchanged",
    }


@router.get("/policy")
async def get_sync_policy(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: models.User = Depends(get_current_user),
):
    _require_sync_manage(db, pid, user)

    setting = (
        db.query(models.GlobalSetting)
        .filter(models.GlobalSetting.key == f"sync_policy:{pid}")
        .first()
    )
    if not setting:
        return {
            "pid": pid,
            "sync_entities": [],
            "direction": "bidirectional",
            "conflict_resolution": "manual",
        }
    return {"pid": pid, **setting.value}


@router.put("/policy")
async def update_sync_policy(
    body: dict,
    db: Annotated[Session, Depends(get_db)],
    user: models.User = Depends(get_current_user),
):
    pid = body.get("pid", "")
    _require_sync_manage(db, pid, user)

    sync_entities = body.get("sync_entities", [])
    direction = body.get("direction", "bidirectional")
    conflict_resolution = body.get("conflict_resolution", "manual")

    if direction not in ("bidirectional", "push_only", "pull_only"):
        raise HTTPException(status_code=400, detail="Invalid direction")
    if conflict_resolution not in ("manual", "local_wins", "remote_wins"):
        raise HTTPException(status_code=400, detail="Invalid conflict_resolution")

    policy_value = {
        "sync_entities": sync_entities,
        "direction": direction,
        "conflict_resolution": conflict_resolution,
    }

    key = f"sync_policy:{pid}"
    setting = db.query(models.GlobalSetting).filter(models.GlobalSetting.key == key).first()
    if setting:
        setting.value = policy_value
    else:
        setting = models.GlobalSetting(key=key, value=policy_value)
        db.add(setting)
    db.commit()

    log_event(db, pid, user.username, "sync", "policy_updated", f"Sync policy updated for {pid}")
    log_operations(db, "sync.policy_updated", project_id=pid, user_id=user.id, detail=policy_value)

    return {"pid": pid, **policy_value}
