from __future__ import annotations

from dataclasses import dataclass, field

from .definition import PlaybookDefinition, StepDef


@dataclass
class ValidationIssue:
    level: str  # "error" | "warning"
    step_id: str
    message: str


@dataclass
class ValidationResult:
    ok: bool = True
    errors: list[ValidationIssue] = field(default_factory=list)
    warnings: list[ValidationIssue] = field(default_factory=list)

    def add_error(self, step_id: str, message: str):
        self.errors.append(ValidationIssue("error", step_id, message))
        self.ok = False

    def add_warning(self, step_id: str, message: str):
        self.warnings.append(ValidationIssue("warning", step_id, message))


_STEP_TYPES = {"action", "delay", "if", "loop", "call"}
_ON_ERROR_VALUES = {"stop", "continue", "retry"}
_VALID_EVENTS = {
    "host.created",
    "host.updated",
    "host.deleted",
    "host.status_changed",
    "cred.created",
    "cred.updated",
    "cred.deleted",
    "finding.created",
    "finding.updated",
    "finding.deleted",
    "note.created",
    "note.deleted",
    "job.created",
    "job.done",
    "job.failed",
    "playbook_run.done",
    "playbook_run.failed",
    "object.created",
    "object.updated",
    "object.deleted",
}


def _check_step(
    step: StepDef,
    available_tools: set[str],
    available_playbooks: set[str],
    seen_ids: set[str],
    declared_inputs: set[str],
    result: ValidationResult,
):
    if not step.id:
        result.add_error("", "Step without id")
        return

    if step.id in seen_ids:
        result.add_error(step.id, f"Duplicate step id: {step.id}")
        return
    seen_ids.add(step.id)

    if step.type not in _STEP_TYPES:
        result.add_error(step.id, f"Unknown step type: {step.type}")
        return

    if step.type == "action":
        if not step.action:
            result.add_error(step.id, "Action step missing 'action' field")
        elif step.action not in available_tools:
            result.add_error(step.id, f"Action '{step.action}' is not registered in tool registry")
        if step.on_error not in _ON_ERROR_VALUES:
            result.add_error(step.id, f"Invalid on_error value: {step.on_error}")

    elif step.type == "call":
        if not step.playbook_id:
            result.add_error(step.id, "Call step missing 'playbook_id'")
        elif step.playbook_id not in available_playbooks:
            result.add_error(step.id, f"Referenced playbook '{step.playbook_id}' not found")

    elif step.type == "delay":
        if step.duration <= 0:
            result.add_warning(step.id, "Delay duration is zero or negative")

    elif step.type == "if":
        if not step.condition:
            result.add_error(step.id, "If step missing 'condition'")
        if not step.then and not step.else_:
            result.add_warning(step.id, "If step has no 'then' or 'else' branch (dead branch)")
        for child in step.then:
            _check_step(
                child, available_tools, available_playbooks, seen_ids, declared_inputs, result
            )
        for child in step.else_:
            _check_step(
                child, available_tools, available_playbooks, seen_ids, declared_inputs, result
            )

    elif step.type == "loop":
        if not step.loop_over:
            result.add_error(step.id, "Loop step missing 'loop_over'")
        if not step.loop_body:
            result.add_warning(step.id, "Loop step has empty body")
        for child in step.loop_body:
            _check_step(
                child, available_tools, available_playbooks, seen_ids, declared_inputs, result
            )

    if step.retry_count > 0 and step.retry_delay <= 0:
        result.add_warning(step.id, "Retry delay is zero — may cause excessive load")


def _collect_step_ids(steps: list[StepDef], ids: set[str]):
    for s in steps:
        ids.add(s.id)
        _collect_step_ids(s.then, ids)
        _collect_step_ids(s.else_, ids)
        _collect_step_ids(s.loop_body, ids)


def _iter_all_steps(steps: list[StepDef]):
    for s in steps:
        yield s
        yield from _iter_all_steps(s.then)
        yield from _iter_all_steps(s.else_)
        yield from _iter_all_steps(s.loop_body)


def build_dependency_graph(automations: dict[str, PlaybookDefinition]) -> dict[str, set[str]]:
    """Cross-automation "leads-to" graph: an edge A -> B means running A can
    lead to B running, either because A has a `call` step invoking B
    (direct, synchronous), or B has a `cascade` trigger naming A (B fires
    after A finishes). Both are cycle-relevant the same way — previously
    only the "call" chain had *runtime* cycle protection
    (executor.py::_exec_call's call_stack); cascade triggers had none at
    all, and neither had a *static* check before an automation could be
    switched on (2026-08-19)."""
    graph: dict[str, set[str]] = {aid: set() for aid in automations}
    for aid, defn in automations.items():
        for step in _iter_all_steps(defn.steps):
            if step.type == "call" and step.playbook_id:
                graph.setdefault(aid, set()).add(step.playbook_id)
        for trig in defn.triggers:
            if trig.type == "cascade" and trig.playbook_id:
                graph.setdefault(trig.playbook_id, set()).add(aid)
    return graph


def find_cycle_through(graph: dict[str, set[str]], start: str) -> list[str] | None:
    """DFS for a cycle that passes back through `start`. Returns the path
    (start -> ... -> start) if one exists, else None."""
    stack: list[tuple[str, list[str]]] = [(start, [start])]
    while stack:
        node, path = stack.pop()
        for nxt in graph.get(node, ()):
            if nxt == start:
                return [*path, nxt]
            if nxt in path:
                continue  # a cycle not involving `start` — not this check's concern
            stack.append((nxt, [*path, nxt]))
    return None


def validate_definition(
    defn: PlaybookDefinition,
    available_tools: set[str] | None = None,
    available_playbooks: set[str] | None = None,
) -> ValidationResult:
    result = ValidationResult()

    if available_tools is None:
        from ..ai.tool_registry import tool_registry

        available_tools = set(tool_registry.list_names())

    if available_playbooks is None:
        available_playbooks = set()

    if not defn.steps:
        result.add_error("", "Playbook has no steps")
        return result

    seen_ids: set[str] = set()
    for step in defn.steps:
        _check_step(step, available_tools, available_playbooks, seen_ids, set(), result)

    # Check triggers
    if not defn.triggers:
        result.add_warning("", "No triggers defined — playbook can only be run manually")

    for trig in defn.triggers:
        if trig.type == "event":
            if not trig.event:
                result.add_error("", "Event trigger missing 'event' field")
            elif trig.event not in _VALID_EVENTS:
                result.add_warning("", f"Event '{trig.event}' is not in the known events list")
        elif trig.type == "schedule":
            if not trig.cron:
                result.add_error("", "Schedule trigger missing 'cron' field")
            else:
                try:
                    from ..cron_utils import validate_cron

                    if not validate_cron(trig.cron):
                        result.add_error("", f"Invalid cron expression: {trig.cron}")
                except Exception:
                    result.add_error("", f"Invalid cron expression: {trig.cron}")
        elif trig.type == "cascade":
            if not trig.playbook_id:
                result.add_error("", "Cascade trigger missing 'playbook_id'")

    return result
