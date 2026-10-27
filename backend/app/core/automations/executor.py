from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from ..ai.tool_registry import tool_registry
from .conditions import evaluate_conditions, resolve_value
from .definition import StepDef

logger = logging.getLogger(__name__)


async def execute_step(
    db: Session,
    pid: str,
    step: StepDef,
    context: dict,
    call_stack: set | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Execute a single step and return a result dict.

    Returns: {"step_id", "type", "status", "result", "error", "duration"}
    """
    started = datetime.now(UTC)

    try:
        if step.type == "action":
            if dry_run:
                resolved = resolve_value(step.params, context)
                result = {
                    "dry_run": True,
                    "action": step.action,
                    "params": resolved,
                    "would_execute": True,
                }
            else:
                result = await _exec_action(db, pid, step, context)
        elif step.type == "delay":
            if dry_run:
                result = {"dry_run": True, "would_delay": step.duration}
            else:
                await asyncio.sleep(step.duration)
                result = {"delayed": step.duration}
        elif step.type == "if":
            result = await _exec_if(db, pid, step, context, call_stack=call_stack, dry_run=dry_run)
        elif step.type == "loop":
            result = await _exec_loop(
                db, pid, step, context, call_stack=call_stack, dry_run=dry_run
            )
        elif step.type == "call":
            if dry_run:
                result = {"dry_run": True, "would_call": step.playbook_id}
            else:
                result = await _exec_call(db, pid, step, context, call_stack=call_stack)
        else:
            raise ValueError(f"Unknown step type: {step.type}")

        duration = (datetime.now(UTC) - started).total_seconds()
        return {
            "step_id": step.id,
            "type": step.type,
            "status": "success",
            "result": result,
            "error": None,
            "duration": round(duration, 3),
        }

    except Exception as e:
        logger.exception("[playbook] step %s failed", step.id)
        duration = (datetime.now(UTC) - started).total_seconds()
        return {
            "step_id": step.id,
            "type": step.type,
            "status": "failed",
            "result": None,
            "error": str(e),
            "duration": round(duration, 3),
        }


async def _exec_action(
    db: Session,
    pid: str,
    step: StepDef,
    context: dict,
) -> Any:
    params = resolve_value(step.params, context)

    attempts = step.retry_count + 1
    last_error: Exception | None = None

    for attempt in range(attempts):
        try:
            result = await tool_registry.execute(db, pid, step.action, params)
            if isinstance(result, dict) and result.get("error"):
                raise RuntimeError(result["error"])
            return result
        except Exception as e:
            last_error = e
            if attempt < attempts - 1:
                await asyncio.sleep(step.retry_delay)
            else:
                raise

    raise last_error  # type: ignore[misc]


async def _exec_if(
    db: Session,
    pid: str,
    step: StepDef,
    context: dict,
    call_stack: set | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    if step.condition is None:
        cond_result = True
    else:
        cond_result = evaluate_conditions([step.condition], context)

    branch = step.then if cond_result else step.else_
    branch_results = []

    for child in branch:
        child_result = await execute_step(
            db, pid, child, context, call_stack=call_stack, dry_run=dry_run
        )
        branch_results.append(child_result)
        if child_result["status"] == "failed":
            on_err = child.on_error
            if on_err == "stop":
                break

    return {
        "condition_met": cond_result,
        "branch": "then" if cond_result else "else",
        "steps": branch_results,
    }


async def _exec_loop(
    db: Session,
    pid: str,
    step: StepDef,
    context: dict,
    call_stack: set | None = None,
    dry_run: bool = False,
) -> dict[str, Any]:
    collection = resolve_value(step.loop_over, context)
    if not isinstance(collection, (list, tuple)):
        return {"iterations": 0, "results": []}

    loop_results = []
    for i, item in enumerate(collection):
        iter_context = {**context, step.loop_var: item, "index": i}
        for child in step.loop_body:
            child_result = await execute_step(
                db, pid, child, iter_context, call_stack=call_stack, dry_run=dry_run
            )
            loop_results.append(child_result)
            if child_result["status"] == "failed" and child.on_error == "stop":
                break

    return {"iterations": len(collection), "results": loop_results}


async def _exec_call(
    db: Session,
    pid: str,
    step: StepDef,
    context: dict,
    call_stack: set | None = None,
) -> Any:
    from ...models import PlaybookAutomation

    # ── Cycle detection (check before DB query) ──
    active_stack = call_stack or set()
    if step.playbook_id in active_stack:
        raise ValueError(
            f"Cascading cycle detected: playbook '{step.playbook_id}' is already "
            f"in the call chain ({' → '.join(active_stack)} → {step.playbook_id})"
        )

    target = (
        db.query(PlaybookAutomation)
        .filter(
            PlaybookAutomation.id == step.playbook_id,
            PlaybookAutomation.pid == pid,
        )
        .first()
    )
    if not target:
        raise ValueError(f"Playbook '{step.playbook_id}' not found")

    active_stack = active_stack | {target.id}

    from .engine import PlaybookEngine

    engine = PlaybookEngine(db)
    run = await engine.execute(
        automation=target,
        pid=pid,
        trigger_type="cascade",
        trigger_data={"caller_step_id": step.id, "caller_context": {}},
        triggered_by="cascade",
        extra_context=context,
        call_stack=active_stack,
    )
    return {"run_id": run.id, "status": run.status}
