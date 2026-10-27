import asyncio
import logging

from sqlalchemy.orm import Session

from .. import models
from ..ws import manager
from .audit_log import compute_integrity
from .audit_log import persist as _audit_persist
from .utils import new_id, ts_now

logger = logging.getLogger(__name__)

_main_loop: asyncio.AbstractEventLoop | None = None


def set_main_loop(loop: asyncio.AbstractEventLoop):
    global _main_loop
    _main_loop = loop


def log_event(
    db: Session,
    pid: str,
    username: str | None,
    entity: str,
    action: str,
    label: str,
    meta: dict | None = None,
    ts: str | None = None,
):
    eid = new_id("evt")
    # ts override: sources that KNOW when the event actually happened
    # (e.g. workstation actions harvested from the machine's own audit
    # log) pass the real time — otherwise the timeline shows harvest
    # time, lagging the command by up to a harvest cycle.
    ts = ts or ts_now()
    event_dict = {
        "id": eid,
        "pid": pid,
        "username": username,
        "entity": entity,
        "action": action,
        "label": label,
        "meta": meta or {},
        "ts": ts,
    }
    integrity = compute_integrity(event_dict)
    if integrity:
        event_dict["integrity"] = integrity

    db.add(models.TimelineEvent(**event_dict))

    # Persist to secondary channels (append-only file + optional S3).
    # Best-effort: never raise so a logging failure can't abort a DB transaction.
    try:
        _audit_persist(event_dict)
    except Exception as e:
        logger.debug("audit persist (secondary channel) failed for event %s: %s", eid, e)

    # ── Fire-and-forget: trigger automations on {entity}.{action} ──
    # Skip internal automation events to avoid log_event→fire_event recursion
    # (the engine calls log_event after execution; those produce playbook_v2_run.*
    # events which could re-trigger if someone configures them, but that's
    # intentional — they won't recurse because fire_event uses its own session).
    if entity != "playbook_v2_run":
        try:
            _trigger_automations(pid, entity, action, label, meta)
        except Exception:
            logger.debug("[events] automation trigger hook failed", exc_info=True)


def bcast(pid: str, entity: str, action: str, data: dict, ws=None):
    """Fire-and-forget WebSocket broadcast from sync endpoints or threads."""
    msg = {"pid": pid, "entity": entity, "action": action, "data": data}
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = _main_loop
    if loop is None or not loop.is_running():
        logger.debug("bcast skipped: no event loop (pid=%s entity=%s)", pid, entity)
        return
    loop.call_soon_threadsafe(asyncio.ensure_future, manager.broadcast(pid, msg, exclude=ws))


def _trigger_automations(pid: str, entity: str, action: str, label: str, meta: dict | None):
    """Fire-and-forget: schedule playbook automation check on the event loop.

    Constructs event name as ``{entity}.{action}`` and passes the meta dict
    as event data so playbooks can reference ``{{event.data.xxx}}``.
    """
    loop = _main_loop
    if loop is None or not loop.is_running():
        return

    event_name = f"{entity}.{action}"
    event_data = {"entity": entity, "action": action, "label": label, **(meta or {})}

    from .automations.engine import fire_event_from_sync

    loop.call_soon_threadsafe(
        asyncio.ensure_future,
        fire_event_from_sync(pid, event_name, event_data),
    )


def bcast_batch(pid: str, events: list[tuple[str, str, dict]], ws=None):
    """Coalesce many per-entity broadcasts into one envelope.

    Bulk imports / smart-build / batch_exec used to fire one bcast() per
    row, which means N Redis publish() round-trips + N per-connection
    iterations. Most callers don't need per-event ordering inside the
    batch — they just need everyone to learn about the same set of new
    rows. This API sends a single `{type:'batch', events:[{entity,action,data}, …]}`
    message; the frontend dispatch loop unwraps it.

    No-ops on empty input. Falls back to one bcast per event if loop is
    unavailable so writeback paths still publish even in sync contexts.
    """
    if not events:
        return
    msg = {
        "pid": pid,
        "type": "batch",
        "events": [{"entity": e, "action": a, "data": d} for (e, a, d) in events],
    }
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = _main_loop
    if loop is None or not loop.is_running():
        for e, a, d in events:
            bcast(pid, e, a, d, ws=ws)
        return
    loop.call_soon_threadsafe(asyncio.ensure_future, manager.broadcast(pid, msg, exclude=ws))
