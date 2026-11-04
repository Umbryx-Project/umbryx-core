from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from ...core.access import user_has_permission
from ...core.events import bcast, log_event
from ...core.utils import new_id
from ...models import PlaybookAutomation, PlaybookRunV2, User
from .conditions import evaluate_conditions
from .definition import PlaybookDefinition
from .executor import execute_step

logger = logging.getLogger(__name__)

# ── In-process tracking for cycle detection & rate limiting ───────────
_running_automations: set[str] = set()
_pending_debounce: dict[str, asyncio.Task] = {}
_rate_tracker: dict[str, list[float]] = {}


def _is_rate_limited(key: str, max_per_hour: int) -> bool:
    if max_per_hour <= 0:
        return False
    now = time.monotonic()
    cutoff = now - 3600
    hits = [t for t in _rate_tracker.get(key, []) if t > cutoff]
    _rate_tracker[key] = hits
    if len(hits) >= max_per_hour:
        return True
    hits.append(now)
    return False


def _count_active_runs(db: Session, automation_id: str) -> int:
    return (
        db.query(PlaybookRunV2)
        .filter(
            PlaybookRunV2.automation_id == automation_id,
            PlaybookRunV2.status.in_(["pending", "running"]),
        )
        .count()
    )


class PlaybookEngine:
    """Orchestrates playbook execution: trigger → conditions → steps → log."""

    def __init__(self, db: Session):
        self.db = db

    async def execute(
        self,
        automation: PlaybookAutomation,
        pid: str,
        trigger_type: str = "manual",
        trigger_data: dict | None = None,
        triggered_by: str = "manual",
        extra_context: dict | None = None,
        call_stack: set[str] | None = None,
        cascade_chain: set[str] | None = None,
        dry_run: bool = False,
    ) -> PlaybookRunV2:
        defn = PlaybookDefinition.from_dict(automation.definition or {})

        # Unattended triggers (event/schedule/cascade) run with nobody at
        # the keyboard to hold accountable — a manual /run call is already
        # gated by the *caller's own* check_pid_access("playbooks.run") at
        # the router, but nothing re-checked that an automation's owner
        # still actually has permission to run it by the time an event
        # fires, possibly long after creation (role downgraded, removed
        # from the project, etc.). An automation must never end up with
        # more effective reach than its owner currently has (2026-08-19).
        if not dry_run and trigger_type in ("event", "schedule", "cascade"):
            denial = self._owner_permission_denial(automation, pid)
            if denial:
                return self._record_denied_run(
                    automation, pid, trigger_type, trigger_data, triggered_by, denial
                )

        context: dict[str, Any] = {
            "event": trigger_data or {},
            "trigger": {"type": trigger_type, "by": triggered_by},
            "project": {"id": pid},
            "now": datetime.now(UTC).isoformat(),
        }
        if extra_context:
            context.update(extra_context)

        run = PlaybookRunV2(
            id=new_id("pbr"),
            automation_id=automation.id,
            pid=pid,
            trigger_type=trigger_type,
            trigger_data=trigger_data or {},
            status="running",
            started_at=datetime.now(UTC),
            triggered_by=triggered_by,
            context=context,
            steps_log=[],
        )
        self.db.add(run)

        automation.last_run_at = datetime.now(UTC)
        if not dry_run:
            automation.last_run_status = "running"
            automation.run_count = (automation.run_count or 0) + 1
        self.db.commit()

        _running_automations.add(automation.id)
        bcast(
            pid,
            "playbook_v2_run",
            "create",
            {"id": run.id, "automation_id": automation.id, "status": "running"},
        )

        try:
            # Evaluate pre-conditions
            if not evaluate_conditions(defn.conditions, context):
                run.status = "skipped"
                run.finished_at = datetime.now(UTC)
                run.error = "Conditions not met"
                self.db.commit()
                bcast(pid, "playbook_v2_run", "update", {"id": run.id, "status": "skipped"})
                return run

            # Execute steps
            steps_log: list[dict] = []
            global_on_error = defn.on_step_error
            active_call_stack = call_stack or set()

            for step in defn.steps:
                step_result = await execute_step(
                    self.db, pid, step, context, call_stack=active_call_stack, dry_run=dry_run
                )
                steps_log.append(step_result)
                context[step.id] = {"result": step_result.get("result")}

                run.steps_log = steps_log
                self.db.commit()

                if step_result["status"] == "failed":
                    on_err = step.on_error or global_on_error
                    if on_err == "stop":
                        run.status = "failed"
                        run.error = f"Step '{step.id}' failed: {step_result.get('error', '')}"
                        break
                    # continue or retry (retry already handled in executor)

            else:
                run.status = "dry_run" if dry_run else "success"

            run.steps_log = steps_log
            run.finished_at = datetime.now(UTC)
            automation.last_run_status = run.status if not dry_run else automation.last_run_status
            self.db.commit()

            log_event(
                self.db,
                pid,
                triggered_by,
                entity="playbook_v2_run",
                action=run.status,
                label=f"Playbook '{automation.name}' — {run.status}",
                meta={"run_id": run.id, "automation_id": automation.id, "trigger": trigger_type},
            )

            bcast(
                pid,
                "playbook_v2_run",
                "update",
                {
                    "id": run.id,
                    "status": run.status,
                    "automation_id": automation.id,
                },
            )

        except Exception as e:
            logger.exception("[playbook_v2] execution error")
            run.status = "failed"
            run.error = str(e)
            run.finished_at = datetime.now(UTC)
            automation.last_run_status = "failed"
            self.db.commit()
            bcast(pid, "playbook_v2_run", "update", {"id": run.id, "status": "failed"})

        finally:
            _running_automations.discard(automation.id)

        if not dry_run and run.status == "success":
            await self._fire_cascade(automation, pid, run, cascade_chain or set())

        return run

    async def _fire_cascade(
        self,
        source: PlaybookAutomation,
        pid: str,
        source_run: PlaybookRunV2,
        cascade_chain: set[str],
    ) -> None:
        """Fire every enabled automation whose trigger is
        ``{"type": "cascade", "playbook_id": source.id}`` — this is the
        declarative counterpart to the "call" step type (which invokes
        another playbook synchronously, from *inside* a step). The
        `cascade` trigger type was already modeled and validated
        (definition.py/validator.py) but nothing ever actually fired it —
        the same "exists in data, never wired to the real flow" pattern
        already found elsewhere in this codebase (2026-08-19).

        ``cascade_chain`` guards against A-cascades-B-cascades-A cycles
        across *separate* automations, the same way ``call_stack`` guards
        cycles across "call" steps within one execution.
        """
        chain = cascade_chain | {source.id}
        candidates = (
            self.db.query(PlaybookAutomation)
            .filter(PlaybookAutomation.pid == pid, PlaybookAutomation.enabled.is_(True))
            .all()
        )
        for auto in candidates:
            if auto.id in chain:
                continue
            defn = PlaybookDefinition.from_dict(auto.definition or {})
            if not any(t.type == "cascade" and t.playbook_id == source.id for t in defn.triggers):
                continue
            if auto.id in _running_automations:
                logger.debug(
                    "[playbook_v2] cascade skip %s — already running (cycle prevention)", auto.id
                )
                continue
            engine = PlaybookEngine(self.db)
            try:
                await engine.execute(
                    automation=auto,
                    pid=pid,
                    trigger_type="cascade",
                    trigger_data={
                        "source_automation_id": source.id,
                        "source_run_id": source_run.id,
                    },
                    triggered_by="cascade",
                    cascade_chain=chain,
                )
            except Exception:
                logger.exception("[playbook_v2] cascade execution failed for %s", auto.id)

    def _owner_permission_denial(self, automation: PlaybookAutomation, pid: str) -> str | None:
        """Return a human-readable denial reason, or None if the
        automation's owner is still entitled to run it."""
        if not automation.owner_id:
            return "Automation has no owner on record"
        owner = self.db.query(User).filter(User.id == automation.owner_id, User.active).first()
        if not owner:
            return "Owner account is inactive or no longer exists"
        if not user_has_permission(self.db, pid, owner, "playbooks.run"):
            return "Owner no longer has permission to run playbooks on this project"
        return None

    def _record_denied_run(
        self,
        automation: PlaybookAutomation,
        pid: str,
        trigger_type: str,
        trigger_data: dict | None,
        triggered_by: str,
        reason: str,
    ) -> PlaybookRunV2:
        run = PlaybookRunV2(
            id=new_id("pbr"),
            automation_id=automation.id,
            pid=pid,
            trigger_type=trigger_type,
            trigger_data=trigger_data or {},
            status="failed",
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
            error=f"Blocked: {reason}",
            triggered_by=triggered_by,
            context={},
            steps_log=[],
        )
        self.db.add(run)
        automation.last_run_at = datetime.now(UTC)
        automation.last_run_status = "failed"
        automation.run_count = (automation.run_count or 0) + 1
        self.db.commit()
        log_event(
            self.db,
            pid,
            triggered_by,
            entity="playbook_v2_run",
            action="failed",
            label=f"Playbook '{automation.name}' — blocked: {reason}",
            meta={"run_id": run.id, "automation_id": automation.id, "trigger": trigger_type},
        )
        bcast(pid, "playbook_v2_run", "update", {"id": run.id, "status": "failed"})
        return run

    def cancel_run(self, run_id: str) -> bool:
        run = self.db.query(PlaybookRunV2).filter(PlaybookRunV2.id == run_id).first()
        if not run:
            return False
        if run.status in ("pending", "running"):
            run.status = "cancelled"
            run.finished_at = datetime.now(UTC)
            self.db.commit()
            bcast(run.pid, "playbook_v2_run", "update", {"id": run.id, "status": "cancelled"})
        return True

    def cancel_all_for_automation(self, automation_id: str) -> int:
        runs = (
            self.db.query(PlaybookRunV2)
            .filter(
                PlaybookRunV2.automation_id == automation_id,
                PlaybookRunV2.status.in_(["pending", "running"]),
            )
            .all()
        )
        count = 0
        for run in runs:
            run.status = "cancelled"
            run.finished_at = datetime.now(UTC)
            count += 1
        if count:
            self.db.commit()
        return count


def check_event_triggers(
    db: Session,
    pid: str,
    event_name: str,
    event_data: dict,
) -> list[PlaybookAutomation]:
    """Find enabled playbooks that trigger on a given event."""
    automations = (
        db.query(PlaybookAutomation)
        .filter(
            PlaybookAutomation.pid == pid,
            PlaybookAutomation.enabled.is_(True),
        )
        .all()
    )

    matched: list[PlaybookAutomation] = []
    for auto in automations:
        defn = PlaybookDefinition.from_dict(auto.definition or {})
        for trig in defn.triggers:
            if trig.type == "event" and trig.event == event_name:
                matched.append(auto)
                break

    return matched


async def fire_event(
    db: Session,
    pid: str,
    event_name: str,
    event_data: dict,
):
    """Fire event-triggered playbooks with cycle detection, debounce & rate limiting."""
    matched = check_event_triggers(db, pid, event_name, event_data)

    for auto in matched:
        # ── Cycle detection: skip if already running ──
        if auto.id in _running_automations:
            logger.debug("[playbook_v2] skip %s — already running (cycle prevention)", auto.id)
            continue

        defn = PlaybookDefinition.from_dict(auto.definition or {})
        trig = next(
            (t for t in defn.triggers if t.type == "event" and t.event == event_name),
            None,
        )
        if not trig:
            continue

        # ── Max concurrent check ──
        if defn.max_concurrent > 0:
            active = _count_active_runs(db, auto.id)
            if active >= defn.max_concurrent:
                logger.debug(
                    "[playbook_v2] skip %s — max_concurrent=%d reached",
                    auto.id,
                    defn.max_concurrent,
                )
                continue

        # ── Debounce ──
        if trig.debounce_ms > 0:
            debounce_key = f"{pid}:{event_name}:{auto.id}"
            existing = _pending_debounce.get(debounce_key)
            if existing and not existing.done():
                existing.cancel()
            _pending_debounce[debounce_key] = asyncio.create_task(
                _debounced_fire(
                    pid,
                    auto.id,
                    event_name,
                    event_data,
                    trig.debounce_ms / 1000,
                    trig.rate_limit_per_hour,
                )
            )
        else:
            # ── Rate limiting (at execution time) ──
            rate_key = f"{pid}:{auto.id}"
            if _is_rate_limited(rate_key, trig.rate_limit_per_hour):
                logger.info(
                    "[playbook_v2] skip %s — rate limit (%d/h) reached",
                    auto.id,
                    trig.rate_limit_per_hour,
                )
                continue

            engine = PlaybookEngine(db)
            try:
                await engine.execute(
                    automation=auto,
                    pid=pid,
                    trigger_type="event",
                    trigger_data={"event": event_name, "data": event_data},
                    triggered_by="system",
                )
            except Exception:
                logger.exception("[playbook_v2] event-triggered execution failed for %s", auto.id)


async def _debounced_fire(
    pid: str,
    automation_id: str,
    event_name: str,
    event_data: dict,
    delay: float,
    rate_limit_per_hour: int = 0,
):
    """Wait *delay* seconds, then fire the automation. Cancelled if superseded."""
    try:
        await asyncio.sleep(delay)
    except asyncio.CancelledError:
        return

    debounce_key = f"{pid}:{event_name}:{automation_id}"
    _pending_debounce.pop(debounce_key, None)

    # ── Rate limiting (at execution time, after debounce) ──
    rate_key = f"{pid}:{automation_id}"
    if _is_rate_limited(rate_key, rate_limit_per_hour):
        logger.info(
            "[playbook_v2] debounced fire skip %s — rate limit (%d/h) reached",
            automation_id,
            rate_limit_per_hour,
        )
        return

    if automation_id in _running_automations:
        logger.debug("[playbook_v2] debounced fire skip %s — already running", automation_id)
        return

    from ...database import SessionLocal

    db = SessionLocal()
    try:
        auto = db.query(PlaybookAutomation).filter(PlaybookAutomation.id == automation_id).first()
        if not auto or not auto.enabled:
            return
        engine = PlaybookEngine(db)
        await engine.execute(
            automation=auto,
            pid=pid,
            trigger_type="event",
            trigger_data={"event": event_name, "data": event_data},
            triggered_by="system",
        )
    except Exception:
        logger.exception("[playbook_v2] debounced execution failed for %s", automation_id)
    finally:
        db.close()


async def fire_event_from_sync(
    pid: str,
    event_name: str,
    event_data: dict,
):
    """Create a fresh DB session and fire events.

    Called from ``log_event`` via ``call_soon_threadsafe`` — runs on the
    main event loop after the original DB transaction has flushed.
    """
    from ...database import SessionLocal

    db = SessionLocal()
    try:
        await fire_event(db, pid, event_name, event_data)
    except Exception:
        logger.debug("[playbook_v2] fire_event_from_sync error", exc_info=True)
    finally:
        db.close()
