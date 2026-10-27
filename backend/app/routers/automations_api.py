"""
Playbook Automation v2 router — declarative automation workflows.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Annotated

import yaml
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models
from ..core.access import check_pid_access
from ..core.ai.tool_registry import tool_registry
from ..core.automations import (
    PlaybookDefinition,
    PlaybookEngine,
    build_dependency_graph,
    find_cycle_through,
    parse_definition,
    validate_definition,
)
from ..core.deps import get_current_user
from ..core.utils import new_id
from ..database import get_db

logger = logging.getLogger(__name__)
router = APIRouter(tags=["automations"])


# ── Schemas ───────────────────────────────────────────────────────────


class AutomationCreate(BaseModel):
    name: str
    description: str = ""
    definition: dict = {}
    consent_critical: bool = False


class AutomationUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    definition: dict | None = None
    consent_critical: bool | None = None


class ValidateBody(BaseModel):
    definition: dict


class RunBody(BaseModel):
    context: dict = {}


class DryRunBody(BaseModel):
    context: dict = {}
    event_data: dict = {}


# ── Templates ─────────────────────────────────────────────────────────


_BUILTIN_TEMPLATES = [
    {
        "name": "Notify on Critical Finding",
        "description": "Auto-create a note when a critical finding appears",
        "definition": {
            "triggers": [{"type": "event", "event": "finding.created"}],
            "conditions": [
                {
                    "op": "AND",
                    "rules": [
                        {"field": "{{event.data.severity}}", "operator": "eq", "value": "critical"},
                    ],
                }
            ],
            "steps": [
                {
                    "id": "note",
                    "type": "action",
                    "action": "create_note",
                    "params": {"content": "Critical: {{event.data.title}}"},
                    "on_error": "continue",
                },
            ],
            "settings": {"timeout": 120, "max_concurrent": 1, "on_step_error": "stop"},
        },
    },
    {
        "name": "Tag New Hosts",
        "description": "Automatically tag newly discovered hosts",
        "definition": {
            "triggers": [{"type": "event", "event": "host.created"}],
            "conditions": [],
            "steps": [
                {
                    "id": "tag",
                    "type": "action",
                    "action": "add_host_tag",
                    "params": {"host_id": "{{event.data.id}}", "tag": "auto-discovered"},
                    "on_error": "continue",
                },
            ],
            "settings": {"timeout": 60, "max_concurrent": 5, "on_step_error": "continue"},
        },
    },
    {
        "name": "Daily Host Summary",
        "description": "Create a summary note of all hosts every day at 9am",
        "definition": {
            "triggers": [{"type": "schedule", "cron": "0 9 * * *"}],
            "conditions": [],
            "steps": [
                {
                    "id": "hosts",
                    "type": "action",
                    "action": "list_hosts",
                    "params": {},
                    "on_error": "stop",
                },
                {
                    "id": "summary",
                    "type": "action",
                    "action": "create_note",
                    "params": {"content": "Daily summary created"},
                    "on_error": "continue",
                },
            ],
            "settings": {"timeout": 300, "max_concurrent": 1, "on_step_error": "stop"},
        },
    },
    {
        "name": "Failed Job Watchdog",
        "description": "Note every failed job with its title for the morning review",
        "definition": {
            "triggers": [{"type": "event", "event": "job.failed"}],
            "conditions": [],
            "steps": [
                {
                    "id": "note",
                    "type": "action",
                    "action": "create_note",
                    "params": {
                        "content": "Job failed: {{event.data.title}} — check Jobs for output"
                    },
                    "on_error": "continue",
                },
            ],
            "settings": {"timeout": 60, "max_concurrent": 5, "on_step_error": "continue"},
        },
    },
    {
        "name": "New Credential Alert",
        "description": "Note each captured credential so nothing sits unvalidated",
        "definition": {
            "triggers": [{"type": "event", "event": "cred.created"}],
            "conditions": [],
            "steps": [
                {
                    "id": "note",
                    "type": "action",
                    "action": "create_note",
                    "params": {
                        "content": "New credential captured: {{event.data.username}} — validate it against scope"
                    },
                    "on_error": "continue",
                },
            ],
            "settings": {"timeout": 60, "max_concurrent": 10, "on_step_error": "continue"},
        },
    },
    {
        "name": "Owned Host Confirmation",
        "description": "Tag hosts whose status changed to owned/pwned for the report",
        "definition": {
            "triggers": [{"type": "event", "event": "host.status_changed"}],
            "conditions": [
                {
                    "op": "OR",
                    "rules": [
                        {"field": "{{event.data.status}}", "operator": "eq", "value": "owned"},
                        {"field": "{{event.data.status}}", "operator": "eq", "value": "pwned"},
                    ],
                }
            ],
            "steps": [
                {
                    "id": "tag",
                    "type": "action",
                    "action": "add_host_tag",
                    "params": {"host_id": "{{event.data.id}}", "tag": "owned-confirmed"},
                    "on_error": "continue",
                },
            ],
            "settings": {"timeout": 60, "max_concurrent": 5, "on_step_error": "continue"},
        },
    },
    {
        "name": "Weekly Findings Digest",
        "description": "Monday 9am: pull open findings into a summary note",
        "definition": {
            "triggers": [{"type": "schedule", "cron": "0 9 * * 1"}],
            "conditions": [],
            "steps": [
                {
                    "id": "findings",
                    "type": "action",
                    "action": "list_findings",
                    "params": {},
                    "on_error": "continue",
                },
                {
                    "id": "digest",
                    "type": "action",
                    "action": "create_note",
                    "params": {"content": "Weekly findings digest — see Findings tab for the current list"},
                    "on_error": "continue",
                },
            ],
            "settings": {"timeout": 300, "max_concurrent": 1, "on_step_error": "continue"},
        },
    },
    {
        "name": "Playbook Failure Reporter",
        "description": "Note every failed automation run with its name",
        "definition": {
            "triggers": [{"type": "event", "event": "playbook_run.failed"}],
            "conditions": [],
            "steps": [
                {
                    "id": "note",
                    "type": "action",
                    "action": "create_note",
                    "params": {"content": "Automation run failed: {{event.data.name}} — inspect the run log"},
                    "on_error": "continue",
                },
            ],
            "settings": {"timeout": 60, "max_concurrent": 5, "on_step_error": "continue"},
        },
    },
    {
        "name": "Triage Queue: New Hosts",
        "description": "Tag freshly discovered hosts for the recon queue",
        "definition": {
            "triggers": [{"type": "event", "event": "host.created"}],
            "conditions": [],
            "steps": [
                {
                    "id": "tag",
                    "type": "action",
                    "action": "add_host_tag",
                    "params": {"host_id": "{{event.data.id}}", "tag": "recon-queue"},
                    "on_error": "continue",
                },
                {
                    "id": "note",
                    "type": "action",
                    "action": "create_note",
                    "params": {"content": "New host discovered: {{event.data.hostname}} ({{event.data.ip}})"},
                    "on_error": "continue",
                },
            ],
            "settings": {"timeout": 60, "max_concurrent": 10, "on_step_error": "continue"},
        },
    },
]


# ── Helpers ───────────────────────────────────────────────────────────


def _auto_to_dict(a: models.PlaybookAutomation) -> dict:
    return {
        "id": a.id,
        "pid": a.pid,
        "name": a.name,
        "description": a.description or "",
        "enabled": a.enabled,
        "definition": a.definition or {},
        "owner_id": a.owner_id,
        "version": a.version,
        "consent_critical": a.consent_critical,
        "last_run_at": a.last_run_at.isoformat() if a.last_run_at else None,
        "last_run_status": a.last_run_status or "",
        "run_count": a.run_count or 0,
        "created_at": a.created_at.isoformat() if a.created_at else None,
        "updated_at": a.updated_at.isoformat() if a.updated_at else None,
    }


def _run_to_dict(r: models.PlaybookRunV2) -> dict:
    return {
        "id": r.id,
        "automation_id": r.automation_id,
        "pid": r.pid,
        "trigger_type": r.trigger_type,
        "trigger_data": r.trigger_data or {},
        "status": r.status,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "finished_at": r.finished_at.isoformat() if r.finished_at else None,
        "error": r.error,
        "steps_log": r.steps_log or [],
        "triggered_by": r.triggered_by or "",
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


def _has_critical_action(defn: PlaybookDefinition) -> bool:
    for step in defn.steps:
        if step.type == "action":
            td = tool_registry.get(step.action)
            if td and td.risk.value == "critical":
                return True
        if step.type == "if":
            if _has_critical_action(PlaybookDefinition(steps=step.then)):
                return True
            if _has_critical_action(PlaybookDefinition(steps=step.else_)):
                return True
        if step.type == "loop":
            if _has_critical_action(PlaybookDefinition(steps=step.loop_body)):
                return True
    return False


def _check_cross_automation_cycle(
    db: Session, pid: str, aid: str, candidate_defn: PlaybookDefinition
) -> str | None:
    """Static cycle check across ALL of the project's automations — the
    candidate definition stands in for `aid`'s own (possibly-unsaved)
    definition; every other automation uses its currently-saved one. Only
    the runtime call_stack/cascade_chain guards existed before this
    (2026-08-19) — those stop an already-cyclic setup from looping
    forever once triggered, but never stopped it from being switched on
    in the first place."""
    others = {
        a.id: PlaybookDefinition.from_dict(a.definition or {})
        for a in db.query(models.PlaybookAutomation)
        .filter(models.PlaybookAutomation.pid == pid, models.PlaybookAutomation.id != aid)
        .all()
    }
    others[aid] = candidate_defn
    graph = build_dependency_graph(others)
    cycle = find_cycle_through(graph, aid)
    if cycle:
        return " → ".join(cycle)
    return None


def _get_auto(db: Session, pid: str, aid: str) -> models.PlaybookAutomation:
    auto = (
        db.query(models.PlaybookAutomation)
        .filter(models.PlaybookAutomation.id == aid, models.PlaybookAutomation.pid == pid)
        .first()
    )
    if not auto:
        raise HTTPException(404, "Automation not found")
    return auto


# ── Static routes (before /{aid}) ─────────────────────────────────────


@router.get("/api/projects/{pid}/automations")
def list_automations(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "playbooks.read")
    items = (
        db.query(models.PlaybookAutomation)
        .filter(models.PlaybookAutomation.pid == pid)
        .order_by(models.PlaybookAutomation.created_at.desc())
        .all()
    )
    return {"items": [_auto_to_dict(a) for a in items]}


@router.post("/api/projects/{pid}/automations")
def create_automation(
    pid: str,
    body: AutomationCreate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "playbooks.create")
    auto = models.PlaybookAutomation(
        id=new_id("pba"),
        pid=pid,
        name=body.name,
        description=body.description,
        definition=body.definition,
        owner_id=user.id,
        consent_critical=body.consent_critical,
    )
    db.add(auto)
    db.commit()
    return _auto_to_dict(auto)


@router.get("/api/projects/{pid}/automations/templates")
def list_templates(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "playbooks.read")
    return {"templates": _BUILTIN_TEMPLATES}


@router.get("/api/projects/{pid}/automations/tools")
def list_available_tools(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "playbooks.read")
    return {"tools": tool_registry.to_dict_list()}


@router.post("/api/projects/{pid}/automations/validate-def")
def validate_definition_endpoint(
    pid: str,
    body: ValidateBody,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "playbooks.read")
    defn = parse_definition(body.definition)
    available_tools = set(tool_registry.list_names())
    available_pbs = {
        a.id
        for a in db.query(models.PlaybookAutomation)
        .filter(models.PlaybookAutomation.pid == pid)
        .all()
    }
    result = validate_definition(defn, available_tools, available_pbs)
    return {
        "ok": result.ok,
        "errors": [{"step_id": e.step_id, "message": e.message} for e in result.errors],
        "warnings": [{"step_id": w.step_id, "message": w.message} for w in result.warnings],
        "has_critical": _has_critical_action(defn),
    }


@router.post("/api/projects/{pid}/automations/import")
def import_automation(
    pid: str,
    body: AutomationCreate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "playbooks.create")
    try:
        defn_dict = (
            yaml.safe_load(body.definition) if isinstance(body.definition, str) else body.definition
        )
    except yaml.YAMLError as e:
        raise HTTPException(400, f"Invalid YAML: {e}")
    auto = models.PlaybookAutomation(
        id=new_id("pba"),
        pid=pid,
        name=body.name,
        description=body.description,
        definition=defn_dict,
        owner_id=user.id,
        consent_critical=body.consent_critical,
    )
    db.add(auto)
    db.commit()
    return _auto_to_dict(auto)


@router.post("/api/projects/{pid}/automations/kill-all")
def kill_all(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "playbooks.update")
    automations = (
        db.query(models.PlaybookAutomation)
        .filter(models.PlaybookAutomation.pid == pid, models.PlaybookAutomation.enabled.is_(True))
        .all()
    )
    for a in automations:
        a.enabled = False
    runs = (
        db.query(models.PlaybookRunV2)
        .filter(
            models.PlaybookRunV2.pid == pid, models.PlaybookRunV2.status.in_(["pending", "running"])
        )
        .all()
    )
    for r in runs:
        r.status = "cancelled"
        r.finished_at = datetime.now(UTC)
    db.commit()
    return {"disabled_automations": len(automations), "cancelled_runs": len(runs)}


# ── Dynamic /{aid} routes ─────────────────────────────────────────────


@router.get("/api/projects/{pid}/automations/{aid}")
def get_automation(
    pid: str,
    aid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "playbooks.read")
    return _auto_to_dict(_get_auto(db, pid, aid))


@router.put("/api/projects/{pid}/automations/{aid}")
def update_automation(
    pid: str,
    aid: str,
    body: AutomationUpdate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "playbooks.update")
    auto = _get_auto(db, pid, aid)
    if body.name is not None:
        auto.name = body.name
    if body.description is not None:
        auto.description = body.description
    if body.definition is not None:
        auto.definition = body.definition
        auto.version = (auto.version or 1) + 1
    if body.consent_critical is not None:
        auto.consent_critical = body.consent_critical
    auto.updated_at = datetime.now(UTC)
    db.commit()
    return _auto_to_dict(auto)


@router.delete("/api/projects/{pid}/automations/{aid}")
def delete_automation(
    pid: str,
    aid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "playbooks.delete")
    auto = _get_auto(db, pid, aid)
    auto.enabled = False
    db.delete(auto)
    db.commit()
    return {"ok": True}


@router.post("/api/projects/{pid}/automations/{aid}/enable")
def enable_automation(
    pid: str,
    aid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "playbooks.update")
    auto = _get_auto(db, pid, aid)

    defn = parse_definition(auto.definition or {})
    available_tools = set(tool_registry.list_names())
    available_pbs = {
        a.id
        for a in db.query(models.PlaybookAutomation)
        .filter(models.PlaybookAutomation.pid == pid)
        .all()
    }
    result = validate_definition(defn, available_tools, available_pbs)

    if not result.ok:
        raise HTTPException(
            422,
            detail={
                "message": "Cannot enable: validation errors",
                "errors": [{"step_id": e.step_id, "message": e.message} for e in result.errors],
            },
        )

    cycle = _check_cross_automation_cycle(db, pid, aid, defn)
    if cycle:
        raise HTTPException(
            422,
            detail={
                "message": "Cannot enable: cyclic dependency across automations",
                "errors": [{"step_id": "", "message": f"Cycle detected: {cycle}"}],
            },
        )

    if _has_critical_action(defn) and not auto.consent_critical:
        raise HTTPException(
            403, "Cannot enable: critical-risk actions require consent_critical=true"
        )

    auto.enabled = True
    auto.updated_at = datetime.now(UTC)
    db.commit()
    return {"ok": True, "enabled": True}


@router.post("/api/projects/{pid}/automations/{aid}/disable")
def disable_automation(
    pid: str,
    aid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "playbooks.update")
    auto = _get_auto(db, pid, aid)
    auto.enabled = False
    auto.updated_at = datetime.now(UTC)
    # Disabling is the per-automation kill switch: an operator who hits
    # OFF expects any run already in flight to stop too, not just future
    # triggers to be ignored — same expectation kill-all already sets.
    # PlaybookEngine.cancel_all_for_automation() existed but was never
    # called from any endpoint before this (2026-08-19).
    cancelled = PlaybookEngine(db).cancel_all_for_automation(aid)
    db.commit()
    return {"ok": True, "enabled": False, "cancelled_runs": cancelled}


@router.post("/api/projects/{pid}/automations/{aid}/validate")
def validate_automation(
    pid: str,
    aid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "playbooks.read")
    auto = _get_auto(db, pid, aid)
    defn = parse_definition(auto.definition or {})
    available_tools = set(tool_registry.list_names())
    available_pbs = {
        a.id
        for a in db.query(models.PlaybookAutomation)
        .filter(models.PlaybookAutomation.pid == pid)
        .all()
    }
    result = validate_definition(defn, available_tools, available_pbs)
    errors = [{"step_id": e.step_id, "message": e.message} for e in result.errors]
    cycle = _check_cross_automation_cycle(db, pid, aid, defn)
    if cycle:
        errors.append({"step_id": "", "message": f"Cycle detected: {cycle}"})
    return {
        "ok": result.ok and not cycle,
        "errors": errors,
        "warnings": [{"step_id": w.step_id, "message": w.message} for w in result.warnings],
        "has_critical": _has_critical_action(defn),
    }


@router.post("/api/projects/{pid}/automations/{aid}/run")
async def run_automation(
    pid: str,
    aid: str,
    body: RunBody,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "playbooks.run")
    auto = _get_auto(db, pid, aid)
    engine = PlaybookEngine(db)
    run = await engine.execute(
        automation=auto,
        pid=pid,
        trigger_type="manual",
        trigger_data={"user": user.username},
        triggered_by=user.username,
        extra_context=body.context,
    )
    return _run_to_dict(run)


@router.post("/api/projects/{pid}/automations/{aid}/dry-run")
async def dry_run_automation(
    pid: str,
    aid: str,
    body: DryRunBody,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "playbooks.read")
    auto = _get_auto(db, pid, aid)
    engine = PlaybookEngine(db)
    run = await engine.execute(
        automation=auto,
        pid=pid,
        trigger_type="dry_run",
        trigger_data={"event": body.event_data or "test", "data": body.event_data},
        triggered_by=user.username,
        extra_context=body.context,
        dry_run=True,
    )
    return _run_to_dict(run)


@router.get("/api/projects/{pid}/automations/{aid}/runs")
def list_runs(
    pid: str,
    aid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    status: str | None = Query(None),
):
    check_pid_access(db, pid, user, "playbooks.read")
    q = db.query(models.PlaybookRunV2).filter(
        models.PlaybookRunV2.automation_id == aid,
        models.PlaybookRunV2.pid == pid,
    )
    if status:
        q = q.filter(models.PlaybookRunV2.status == status)
    total = q.count()
    runs = q.order_by(models.PlaybookRunV2.created_at.desc()).offset(offset).limit(limit).all()
    return {"items": [_run_to_dict(r) for r in runs], "total": total}


@router.get("/api/projects/{pid}/automations/{aid}/runs/{rid}")
def get_run(
    pid: str,
    aid: str,
    rid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "playbooks.read")
    run = (
        db.query(models.PlaybookRunV2)
        .filter(
            models.PlaybookRunV2.id == rid,
            models.PlaybookRunV2.automation_id == aid,
            models.PlaybookRunV2.pid == pid,
        )
        .first()
    )
    if not run:
        raise HTTPException(404, "Run not found")
    return _run_to_dict(run)


@router.post("/api/projects/{pid}/automations/{aid}/runs/{rid}/cancel")
def cancel_run(
    pid: str,
    aid: str,
    rid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "playbooks.update")
    engine = PlaybookEngine(db)
    if not engine.cancel_run(rid):
        raise HTTPException(404, "Run not found")
    return {"ok": True}


@router.get("/api/projects/{pid}/automations/{aid}/export")
def export_automation(
    pid: str,
    aid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "playbooks.read")
    auto = _get_auto(db, pid, aid)
    return {
        "name": auto.name,
        "description": auto.description or "",
        "definition": auto.definition or {},
        "version": auto.version,
    }
