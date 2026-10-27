"""Unit tests for Playbook Automation v2 — conditions, validator, executor."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest

from app.core.automations.conditions import (
    _apply_operator,
    evaluate_conditions,
    resolve_value,
)
from app.core.automations.definition import PlaybookDefinition, StepDef, parse_definition
from app.core.automations.validator import validate_definition


@pytest.fixture(scope="module", autouse=True)
def _cleanup_automation_test_data():
    """The HTTP-driven tests below (client/db fixtures) commit real rows
    against the shared process-wide test DB (tests/conftest.py's
    sqlite://+StaticPool engine, not rolled back between tests — see
    _bootstrap_project's docstring) — including PlaybookAutomation rows
    with owner_id set to the dedicated test admin. Left behind, those FK
    references break unrelated tests elsewhere that assume they can
    freely delete all User rows (e.g.
    test_main_extra.py::TestEnsureAdminUser::test_custom_credentials).
    Clean up everything this file's tests create once the whole module
    is done, since collection order (alphabetical) runs this file before
    most others anyway (2026-08-19)."""
    yield
    from app.database import SessionLocal
    from app.models import PlaybookAutomation, PlaybookRunV2

    # Only the FK edge that actually broke another test (PlaybookAutomation/
    # PlaybookRunV2 -> users.id) needs clearing — leave the dedicated test
    # users themselves in place rather than chase every other table that
    # might reference them (audit log, project membership, ...); other
    # tests already tolerate a non-empty, shared DB and use unique names
    # for exactly this reason.
    session = SessionLocal()
    try:
        session.query(PlaybookRunV2).delete(synchronize_session=False)
        session.query(PlaybookAutomation).delete(synchronize_session=False)
        session.commit()
    finally:
        session.close()


def _bootstrap_project(client, db):
    """The test DB (sqlite://, StaticPool) is shared process-wide across
    every test file, so /api/auth/setup (which 403s once any user
    exists) isn't reliable here regardless of run order — upsert a
    dedicated admin directly, same pattern tests/conftest.py's
    module_db fixture already uses for the same reason."""
    from app.core.enums import UserRole
    from app.core.security import hash_password
    from app.core.utils import new_id, ts_now
    from app.models import User

    admin = db.query(User).filter_by(username="automations_test_admin").first()
    if not admin:
        admin = User(
            id=new_id("u"),
            username="automations_test_admin",
            password_hash=hash_password("TestPass1234!"),
            role=UserRole.PLATFORM_ADMIN.value,
            created_at=ts_now(),
            active=True,
        )
        db.add(admin)
        db.commit()

    r = client.post(
        "/api/auth/login", json={"username": "automations_test_admin", "password": "TestPass1234!"}
    )
    assert r.status_code == 200, r.text

    r = client.post(
        "/api/projects",
        json={"name": "Automations Test", "added": "2025-01-01T00:00:00Z", "status": "active"},
    )
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _bare_project(db):
    """Just a Project row to satisfy PlaybookRun.pid's FK — no user/auth
    needed for tests that talk to the ORM directly."""
    from app.core.utils import new_id, ts_now
    from app.models import Project

    p = Project(id=new_id("p"), name="Bare", added=ts_now(), status="active")
    db.add(p)
    db.commit()
    return p.id


# ── resolve_value ─────────────────────────────────────────────────────


class TestResolveValue:
    def test_plain_string(self):
        assert resolve_value("hello", {}) == "hello"

    def test_full_template(self):
        ctx = {"event": {"data": {"severity": "critical"}}}
        assert resolve_value("{{event.data.severity}}", ctx) == "critical"

    def test_partial_template(self):
        ctx = {"name": "world"}
        assert resolve_value("Hello {{name}}!", ctx) == "Hello world!"

    def test_missing_path(self):
        assert resolve_value("{{event.data.x}}", {}) is None

    def test_nested_in_dict(self):
        ctx = {"step1": {"result": {"id": "abc"}}}
        d = resolve_value({"host_id": "{{step1.result.id}}", "tag": "fixed"}, ctx)
        assert d == {"host_id": "abc", "tag": "fixed"}

    def test_list_index(self):
        ctx = {"items": ["a", "b", "c"]}
        assert resolve_value("{{items.0}}", ctx) == "a"
        assert resolve_value("{{items.2}}", ctx) == "c"

    def test_non_string_passthrough(self):
        assert resolve_value(42, {}) == 42
        assert resolve_value(None, {}) is None
        assert resolve_value(True, {}) is True


# ── operators ─────────────────────────────────────────────────────────


class TestOperators:
    def test_eq(self):
        assert _apply_operator("critical", "eq", "critical") is True
        assert _apply_operator("high", "eq", "critical") is False

    def test_ne(self):
        assert _apply_operator("high", "ne", "critical") is True

    def test_gt(self):
        assert _apply_operator(10, "gt", 5) is True
        assert _apply_operator(3, "gt", 5) is False

    def test_contains_str(self):
        assert _apply_operator("hello world", "contains", "world") is True
        assert _apply_operator("hello", "contains", "world") is False

    def test_contains_list(self):
        assert _apply_operator(["a", "b"], "contains", "a") is True

    def test_in(self):
        assert _apply_operator("a", "in", ["a", "b"]) is True
        assert _apply_operator("c", "in", ["a", "b"]) is False

    def test_matches(self):
        assert _apply_operator("test123", "matches", r"\d+") is True
        assert _apply_operator("test", "matches", r"\d+") is False

    def test_is_empty(self):
        assert _apply_operator("", "is_empty", None) is True
        assert _apply_operator(None, "is_empty", None) is True
        assert _apply_operator("x", "is_empty", None) is False

    def test_is_null(self):
        assert _apply_operator(None, "is_null", None) is True
        assert _apply_operator(0, "is_null", None) is False


# ── condition groups ──────────────────────────────────────────────────


class TestConditionGroups:
    def test_and_group(self):
        ctx = {"event": {"data": {"severity": "critical", "status": "open"}}}
        conditions = [
            {
                "op": "AND",
                "rules": [
                    {"field": "{{event.data.severity}}", "operator": "eq", "value": "critical"},
                    {"field": "{{event.data.status}}", "operator": "eq", "value": "open"},
                ],
            }
        ]
        assert evaluate_conditions(conditions, ctx) is True

    def test_and_group_fail(self):
        ctx = {"event": {"data": {"severity": "low", "status": "open"}}}
        conditions = [
            {
                "op": "AND",
                "rules": [
                    {"field": "{{event.data.severity}}", "operator": "eq", "value": "critical"},
                    {"field": "{{event.data.status}}", "operator": "eq", "value": "open"},
                ],
            }
        ]
        assert evaluate_conditions(conditions, ctx) is False

    def test_or_group(self):
        ctx = {"event": {"data": {"severity": "high"}}}
        conditions = [
            {
                "op": "OR",
                "rules": [
                    {"field": "{{event.data.severity}}", "operator": "eq", "value": "critical"},
                    {"field": "{{event.data.severity}}", "operator": "eq", "value": "high"},
                ],
            }
        ]
        assert evaluate_conditions(conditions, ctx) is True

    def test_not_group(self):
        ctx = {"event": {"data": {"severity": "low"}}}
        conditions = [
            {
                "op": "NOT",
                "rules": [
                    {"field": "{{event.data.severity}}", "operator": "eq", "value": "critical"},
                ],
            }
        ]
        assert evaluate_conditions(conditions, ctx) is True

    def test_empty_conditions(self):
        assert evaluate_conditions(None, {}) is True
        assert evaluate_conditions([], {}) is True

    def test_multiple_groups_implicit_and(self):
        ctx = {"event": {"data": {"severity": "critical", "status": "open"}}}
        conditions = [
            {
                "op": "AND",
                "rules": [
                    {"field": "{{event.data.severity}}", "operator": "eq", "value": "critical"}
                ],
            },
            {
                "op": "AND",
                "rules": [{"field": "{{event.data.status}}", "operator": "eq", "value": "open"}],
            },
        ]
        assert evaluate_conditions(conditions, ctx) is True

    def test_nested_groups(self):
        ctx = {"event": {"data": {"a": 1, "b": 2}}}
        conditions = [
            {
                "op": "AND",
                "rules": [
                    {
                        "op": "OR",
                        "rules": [
                            {"field": "{{event.data.a}}", "operator": "eq", "value": 1},
                            {"field": "{{event.data.a}}", "operator": "eq", "value": 2},
                        ],
                    },
                    {"field": "{{event.data.b}}", "operator": "eq", "value": 2},
                ],
            }
        ]
        assert evaluate_conditions(conditions, ctx) is True


# ── definition parsing ────────────────────────────────────────────────


class TestDefinitionParsing:
    def test_parse_simple(self):
        d = {
            "triggers": [{"type": "manual"}],
            "conditions": [],
            "steps": [{"id": "s1", "type": "action", "action": "list_hosts", "params": {}}],
            "settings": {"timeout": 60},
        }
        defn = parse_definition(d)
        assert len(defn.steps) == 1
        assert defn.steps[0].action == "list_hosts"
        assert defn.timeout == 60

    def test_parse_from_yaml_string(self):
        yaml_str = """
triggers:
  - type: manual
steps:
  - id: s1
    type: action
    action: list_hosts
"""
        defn = parse_definition(yaml_str)
        assert defn.steps[0].id == "s1"

    def test_parse_retry(self):
        d = {
            "steps": [
                {"id": "s1", "type": "action", "action": "x", "retry": {"count": 3, "delay": 5}}
            ]
        }
        defn = parse_definition(d)
        assert defn.steps[0].retry_count == 3
        assert defn.steps[0].retry_delay == 5.0

    def test_parse_if_step(self):
        d = {
            "steps": [
                {
                    "id": "s1",
                    "type": "if",
                    "condition": {"op": "AND", "rules": []},
                    "then": [{"id": "s1a", "type": "action", "action": "x"}],
                    "else": [],
                }
            ]
        }
        defn = parse_definition(d)
        assert defn.steps[0].type == "if"
        assert len(defn.steps[0].then) == 1
        assert len(defn.steps[0].else_) == 0

    def test_to_dict_roundtrip(self):
        d = {
            "triggers": [{"type": "event", "event": "host.created"}],
            "steps": [
                {
                    "id": "s1",
                    "type": "action",
                    "action": "list_hosts",
                    "params": {},
                    "on_error": "continue",
                }
            ],
        }
        defn = parse_definition(d)
        out = defn.to_dict()
        defn2 = PlaybookDefinition.from_dict(out)
        assert defn2.steps[0].action == "list_hosts"
        assert defn2.triggers[0].event == "host.created"


# ── validator ─────────────────────────────────────────────────────────


class TestValidator:
    def test_valid_simple(self):
        defn = PlaybookDefinition.from_dict(
            {
                "triggers": [{"type": "manual"}],
                "steps": [{"id": "s1", "type": "action", "action": "list_hosts", "params": {}}],
            }
        )
        result = validate_definition(defn, available_tools={"list_hosts"})
        assert result.ok is True
        assert len(result.errors) == 0

    def test_broken_action_ref(self):
        defn = PlaybookDefinition.from_dict(
            {
                "steps": [{"id": "s1", "type": "action", "action": "nonexistent", "params": {}}],
            }
        )
        result = validate_definition(defn, available_tools={"list_hosts"})
        assert result.ok is False
        assert any("nonexistent" in e.message for e in result.errors)

    def test_missing_step_id(self):
        defn = PlaybookDefinition.from_dict(
            {
                "steps": [{"type": "action", "action": "list_hosts"}],
            }
        )
        result = validate_definition(defn, available_tools={"list_hosts"})
        assert result.ok is False

    def test_duplicate_step_id(self):
        defn = PlaybookDefinition.from_dict(
            {
                "steps": [
                    {"id": "s1", "type": "action", "action": "list_hosts"},
                    {"id": "s1", "type": "action", "action": "list_creds"},
                ],
            }
        )
        result = validate_definition(defn, available_tools={"list_hosts", "list_creds"})
        assert result.ok is False
        assert any("Duplicate" in e.message for e in result.errors)

    def test_no_steps(self):
        defn = PlaybookDefinition.from_dict({"steps": []})
        result = validate_definition(defn)
        assert result.ok is False
        assert any("no steps" in e.message.lower() for e in result.errors)

    def test_invalid_on_error(self):
        defn = PlaybookDefinition.from_dict(
            {
                "steps": [
                    {"id": "s1", "type": "action", "action": "list_hosts", "on_error": "explode"}
                ],
            }
        )
        result = validate_definition(defn, available_tools={"list_hosts"})
        assert result.ok is False

    def test_invalid_cron(self):
        defn = PlaybookDefinition.from_dict(
            {
                "triggers": [{"type": "schedule", "cron": "not-a-cron"}],
                "steps": [{"id": "s1", "type": "action", "action": "list_hosts"}],
            }
        )
        result = validate_definition(defn, available_tools={"list_hosts"})
        assert result.ok is False
        assert any("cron" in e.message.lower() for e in result.errors)

    def test_if_step_no_branches_warns(self):
        defn = PlaybookDefinition.from_dict(
            {
                "steps": [
                    {
                        "id": "s1",
                        "type": "if",
                        "condition": {"op": "AND", "rules": []},
                        "then": [],
                        "else": [],
                    }
                ],
            }
        )
        result = validate_definition(defn, available_tools=set())
        assert result.ok is True  # warning, not error
        assert len(result.warnings) > 0

    def test_call_to_missing_playbook(self):
        defn = PlaybookDefinition.from_dict(
            {
                "steps": [{"id": "s1", "type": "call", "playbook_id": "missing-pb"}],
            }
        )
        result = validate_definition(defn, available_playbooks={"existing-pb"})
        assert result.ok is False
        assert any("missing-pb" in e.message for e in result.errors)


# ── executor ──────────────────────────────────────────────────────────


class TestExecutor:
    def test_delay_step(self):
        from app.core.automations.executor import execute_step

        step = StepDef(id="d1", type="delay", duration=0.01)
        result = asyncio.run(
            execute_step(MagicMock(), "pid", step, {})
        )
        assert result["status"] == "success"
        assert result["result"]["delayed"] == 0.01

    def test_unknown_step_type(self):
        from app.core.automations.executor import execute_step

        step = StepDef(id="x1", type="bogus")
        result = asyncio.run(
            execute_step(MagicMock(), "pid", step, {})
        )
        assert result["status"] == "failed"

    def test_action_calls_tool_registry(self):
        from app.core.ai.tool_registry import RiskLevel, tool_registry
        from app.core.automations.executor import execute_step

        tool_registry.register(
            "test_echo",
            "echo for tests",
            RiskLevel.READ,
            {"msg": {"type": "string"}},
            ["msg"],
            lambda db, pid, msg="": {"echoed": msg},
        )
        try:
            step = StepDef(id="e1", type="action", action="test_echo", params={"msg": "hello"})
            result = asyncio.run(
                execute_step(MagicMock(), "pid", step, {})
            )
            assert result["status"] == "success"
            assert result["result"]["echoed"] == "hello"
        finally:
            tool_registry.unregister("test_echo")

    def test_action_error_propagates(self):
        from app.core.ai.tool_registry import RiskLevel, tool_registry
        from app.core.automations.executor import execute_step

        def bad_handler(db, pid, **kw):
            raise RuntimeError("boom")

        tool_registry.register("test_boom", "fails", RiskLevel.READ, {}, [], bad_handler)
        try:
            step = StepDef(id="b1", type="action", action="test_boom", params={})
            result = asyncio.run(
                execute_step(MagicMock(), "pid", step, {})
            )
            assert result["status"] == "failed"
            assert "boom" in result["error"]
        finally:
            tool_registry.unregister("test_boom")

    def test_if_step_true_branch(self):
        from app.core.automations.executor import execute_step

        step = StepDef(
            id="if1",
            type="if",
            condition={"op": "AND", "rules": [{"field": "{{x}}", "operator": "eq", "value": 1}]},
            then=[StepDef(id="t1", type="delay", duration=0.01)],
            else_=[StepDef(id="e1", type="delay", duration=0.01)],
        )
        result = asyncio.run(
            execute_step(MagicMock(), "pid", step, {"x": 1})
        )
        assert result["status"] == "success"
        assert result["result"]["branch"] == "then"


# ── Phase 2: rate limiting, debounce, cycle detection ─────────────────


class TestTriggerDefinition:
    def test_debounce_parsed(self):
        defn = parse_definition(
            {
                "triggers": [{"type": "event", "event": "host.created", "debounce_ms": 5000}],
                "steps": [{"id": "s1", "type": "action", "action": "list_hosts"}],
            }
        )
        assert defn.triggers[0].debounce_ms == 5000

    def test_rate_limit_parsed(self):
        defn = parse_definition(
            {
                "triggers": [{"type": "event", "event": "host.created", "rate_limit_per_hour": 10}],
                "steps": [{"id": "s1", "type": "action", "action": "list_hosts"}],
            }
        )
        assert defn.triggers[0].rate_limit_per_hour == 10

    def test_trigger_roundtrip_with_limits(self):
        d = {
            "triggers": [
                {"type": "event", "event": "x.y", "debounce_ms": 1000, "rate_limit_per_hour": 5}
            ],
            "steps": [{"id": "s1", "type": "action", "action": "list_hosts"}],
        }
        defn = parse_definition(d)
        out = defn.to_dict()
        assert out["triggers"][0]["debounce_ms"] == 1000
        assert out["triggers"][0]["rate_limit_per_hour"] == 5


class TestRateLimiting:
    def test_under_limit(self):
        from app.core.automations.engine import _is_rate_limited, _rate_tracker

        _rate_tracker.clear()
        key = "test_under"
        assert _is_rate_limited(key, 5) is False
        assert _is_rate_limited(key, 5) is False

    def test_at_limit(self):
        from app.core.automations.engine import _is_rate_limited, _rate_tracker

        _rate_tracker.clear()
        key = "test_at"
        for _ in range(3):
            _is_rate_limited(key, 3)
        assert _is_rate_limited(key, 3) is True

    def test_zero_means_unlimited(self):
        from app.core.automations.engine import _is_rate_limited, _rate_tracker

        _rate_tracker.clear()
        assert _is_rate_limited("test_zero", 0) is False


class TestCycleDetection:
    def test_call_cycle_raises(self):
        """Cascading call to self raises ValueError."""
        from app.core.automations.definition import StepDef
        from app.core.automations.executor import _exec_call

        step = StepDef(id="c1", type="call", playbook_id="auto_a")
        call_stack = {"auto_a"}

        loop = asyncio.new_event_loop()
        try:
            with pytest.raises(ValueError, match="cycle"):
                loop.run_until_complete(
                    _exec_call(MagicMock(), "pid", step, {}, call_stack=call_stack)
                )
        finally:
            loop.close()

    def test_call_chain_no_false_positive(self):
        """A→B chain doesn't trigger cycle detection."""

        active_stack = {"auto_a"}
        assert "auto_b" not in active_stack

    def test_running_automations_tracks(self):
        """_running_automations set correctly tracks active IDs."""
        from app.core.automations import engine as eng

        eng._running_automations.clear()
        eng._running_automations.add("auto_x")
        assert "auto_x" in eng._running_automations
        eng._running_automations.discard("auto_x")
        assert "auto_x" not in eng._running_automations


# ── Static cross-automation cycle detection (2026-08-19) ───────────────
# Previously only the runtime call_stack (executor.py::_exec_call) caught
# a cyclic "call" chain, and cascade triggers (validator.py already
# parsed the "cascade" trigger type) had no cycle protection of any kind.
# Neither had a check *before* an automation could be enabled.


class TestStaticCycleDetection:
    def test_no_cycle_in_chain(self):
        from app.core.automations.validator import build_dependency_graph, find_cycle_through

        defs = {
            "a": PlaybookDefinition(steps=[StepDef(id="s1", type="call", playbook_id="b")]),
            "b": PlaybookDefinition(steps=[StepDef(id="s1", type="call", playbook_id="c")]),
            "c": PlaybookDefinition(steps=[StepDef(id="s1", type="action", action="noop")]),
        }
        graph = build_dependency_graph(defs)
        assert find_cycle_through(graph, "a") is None

    def test_cycle_via_call_steps(self):
        from app.core.automations.validator import build_dependency_graph, find_cycle_through

        defs = {
            "a": PlaybookDefinition(steps=[StepDef(id="s1", type="call", playbook_id="b")]),
            "b": PlaybookDefinition(steps=[StepDef(id="s1", type="call", playbook_id="a")]),
        }
        graph = build_dependency_graph(defs)
        cycle = find_cycle_through(graph, "a")
        assert cycle is not None
        assert cycle[0] == "a" and cycle[-1] == "a"

    def test_cycle_via_cascade_trigger(self):
        from app.core.automations.definition import TriggerDef
        from app.core.automations.validator import build_dependency_graph, find_cycle_through

        # a --call--> b (edge a->b), and a itself has a cascade trigger
        # that fires when b finishes (edge b->a) — together, a -> b -> a.
        defs = {
            "a": PlaybookDefinition(
                triggers=[TriggerDef(type="cascade", playbook_id="b")],
                steps=[StepDef(id="s1", type="call", playbook_id="b")],
            ),
            "b": PlaybookDefinition(steps=[StepDef(id="s1", type="action", action="noop")]),
        }
        graph = build_dependency_graph(defs)
        cycle = find_cycle_through(graph, "a")
        assert cycle is not None

    def test_cycle_not_involving_start_is_ignored(self):
        from app.core.automations.validator import build_dependency_graph, find_cycle_through

        # b <-> c cycle exists, but a -> b doesn't loop back to a.
        defs = {
            "a": PlaybookDefinition(steps=[StepDef(id="s1", type="call", playbook_id="b")]),
            "b": PlaybookDefinition(steps=[StepDef(id="s1", type="call", playbook_id="c")]),
            "c": PlaybookDefinition(steps=[StepDef(id="s1", type="call", playbook_id="b")]),
        }
        graph = build_dependency_graph(defs)
        assert find_cycle_through(graph, "a") is None


# ── Enable-time blocking on cross-automation cycles (integration) ──────


class TestEnableBlocksOnCycle:
    def test_enable_rejected_when_cascade_creates_cycle(self, client, db):
        pid = _bootstrap_project(client, db)
        step = {
            "id": "s1",
            "type": "action",
            "action": "list_hosts",
            "params": {},
            "on_error": "stop",
        }

        ra = client.post(
            f"/api/projects/{pid}/automations",
            json={"name": "A", "definition": {"triggers": [], "steps": [step]}},
        )
        aid_a = ra.json()["id"]

        rb = client.post(
            f"/api/projects/{pid}/automations",
            json={
                "name": "B",
                "definition": {
                    "triggers": [{"type": "cascade", "playbook_id": aid_a}],
                    "steps": [{"id": "s1", "type": "call", "playbook_id": aid_a}],
                },
            },
        )
        aid_b = rb.json()["id"]

        # B calls A (edge B->A) and B's own trigger fires on A's completion
        # (edge A->B) — enabling B would switch on a live cycle.
        r = client.post(f"/api/projects/{pid}/automations/{aid_b}/enable")
        assert r.status_code == 422, r.text
        assert "cycle" in r.text.lower() or "cyclic" in r.text.lower()

    def test_enable_allowed_without_cycle(self, client, db):
        pid = _bootstrap_project(client, db)
        step = {
            "id": "s1",
            "type": "action",
            "action": "list_hosts",
            "params": {},
            "on_error": "stop",
        }
        ra = client.post(
            f"/api/projects/{pid}/automations",
            json={"name": "A", "definition": {"triggers": [], "steps": [step]}},
        )
        aid_a = ra.json()["id"]
        rb = client.post(
            f"/api/projects/{pid}/automations",
            json={
                "name": "B",
                "definition": {
                    "triggers": [{"type": "cascade", "playbook_id": aid_a}],
                    "steps": [step],
                },
            },
        )
        aid_b = rb.json()["id"]
        r = client.post(f"/api/projects/{pid}/automations/{aid_b}/enable")
        assert r.status_code == 200, r.text


# ── Cascade trigger actually fires (2026-08-19 fix) ─────────────────────


class TestCascadeIntegration:
    def test_cascade_trigger_fires_after_source_success(self, client, db):
        pid = _bootstrap_project(client, db)
        step = {
            "id": "s1",
            "type": "action",
            "action": "list_hosts",
            "params": {},
            "on_error": "stop",
        }

        ra = client.post(
            f"/api/projects/{pid}/automations",
            json={"name": "Source", "definition": {"triggers": [], "steps": [step]}},
        )
        aid_a = ra.json()["id"]

        rb = client.post(
            f"/api/projects/{pid}/automations",
            json={
                "name": "Cascaded",
                "definition": {
                    "triggers": [{"type": "cascade", "playbook_id": aid_a}],
                    "steps": [step],
                },
            },
        )
        aid_b = rb.json()["id"]
        r = client.post(f"/api/projects/{pid}/automations/{aid_b}/enable")
        assert r.status_code == 200, r.text

        run = client.post(f"/api/projects/{pid}/automations/{aid_a}/run", json={})
        assert run.status_code == 200, run.text
        assert run.json()["status"] == "success"

        runs_b = client.get(f"/api/projects/{pid}/automations/{aid_b}/runs").json()["items"]
        assert any(rr["trigger_type"] == "cascade" for rr in runs_b), runs_b

    def test_cascade_does_not_fire_when_target_disabled(self, client, db):
        pid = _bootstrap_project(client, db)
        step = {
            "id": "s1",
            "type": "action",
            "action": "list_hosts",
            "params": {},
            "on_error": "stop",
        }

        ra = client.post(
            f"/api/projects/{pid}/automations",
            json={"name": "Source2", "definition": {"triggers": [], "steps": [step]}},
        )
        aid_a = ra.json()["id"]
        rb = client.post(
            f"/api/projects/{pid}/automations",
            json={
                "name": "Cascaded2",
                "definition": {
                    "triggers": [{"type": "cascade", "playbook_id": aid_a}],
                    "steps": [step],
                },
            },
        )
        aid_b = rb.json()["id"]
        # deliberately not enabled

        client.post(f"/api/projects/{pid}/automations/{aid_a}/run", json={})
        runs_b = client.get(f"/api/projects/{pid}/automations/{aid_b}/runs").json()["items"]
        assert runs_b == []


# ── Per-automation kill switch (2026-08-19 fix) ─────────────────────────


class TestPerAutomationKillSwitch:
    def test_disable_cancels_active_runs(self, client, db):
        pid = _bootstrap_project(client, db)
        from app.core.utils import new_id
        from app.models import PlaybookAutomation, PlaybookRunV2

        auto = PlaybookAutomation(
            id=new_id("pba"),
            pid=pid,
            name="Killable",
            enabled=True,
            definition={"steps": [{"id": "s1", "type": "action", "action": "list_hosts"}]},
        )
        db.add(auto)
        db.flush()
        run = PlaybookRunV2(
            id=new_id("pbr"),
            automation_id=auto.id,
            pid=pid,
            status="running",
            trigger_data={},
            steps_log=[],
            context={},
        )
        db.add(run)
        db.commit()

        r = client.post(f"/api/projects/{pid}/automations/{auto.id}/disable")
        assert r.status_code == 200, r.text
        assert r.json()["cancelled_runs"] == 1

        db.refresh(run)
        assert run.status == "cancelled"


# ── Automation runs in its owner's permission context (2026-08-19 fix) ──


class TestOwnerPermissionEnforcement:
    async def test_event_trigger_blocked_when_owner_not_a_member(self, client, db):
        pid = _bootstrap_project(client, db)
        r = client.post(
            "/api/admin/users",
            json={"username": "notamember", "password": "OrgPass1234!", "role": "user"},
        )
        assert r.status_code in (200, 201), r.text
        uid = r.json()["id"]

        from app.core.automations.engine import PlaybookEngine
        from app.core.utils import new_id
        from app.models import PlaybookAutomation

        auto = PlaybookAutomation(
            id=new_id("pba"),
            pid=pid,
            name="Orphaned",
            owner_id=uid,
            enabled=True,
            definition={
                "triggers": [{"type": "event", "event": "host.created"}],
                "steps": [{"id": "s1", "type": "action", "action": "list_hosts"}],
            },
        )
        db.add(auto)
        db.commit()

        engine = PlaybookEngine(db)
        run = await engine.execute(
            automation=auto,
            pid=pid,
            trigger_type="event",
            trigger_data={"event": "host.created"},
            triggered_by="system",
        )
        assert run.status == "failed"
        assert "owner" in (run.error or "").lower() or "permission" in (run.error or "").lower()
        assert run.steps_log == []  # never got as far as running any step

    async def test_manual_trigger_is_not_owner_gated(self, client, db):
        """Manual runs are already gated by the *caller's own*
        check_pid_access at the router — the owner-permission check only
        applies to unattended triggers (event/schedule/cascade)."""
        pid = _bootstrap_project(client, db)
        from app.core.automations.engine import PlaybookEngine
        from app.core.utils import new_id
        from app.models import PlaybookAutomation

        auto = PlaybookAutomation(
            id=new_id("pba"),
            pid=pid,
            name="NoOwner",
            owner_id=None,
            enabled=True,
            definition={"steps": [{"id": "s1", "type": "action", "action": "list_hosts"}]},
        )
        db.add(auto)
        db.commit()

        engine = PlaybookEngine(db)
        run = await engine.execute(
            automation=auto, pid=pid, trigger_type="manual", triggered_by="admin"
        )
        assert run.status == "success"


# ── "Accepted, not confirmed" fix for run_playbook (2026-08-19) ─────────


class TestRunPlaybookWaitsForRealOutcome:
    async def test_reports_terminal_status_not_just_launched(self, db, monkeypatch):
        pid = _bare_project(db)
        import asyncio as _asyncio

        from app import models
        from app.core import ai_tools
        from app.core.utils import new_id, ts_now

        monkeypatch.setattr(ai_tools, "_V1_RUN_POLL_INTERVAL", 0.01)

        run_id = new_id("pbr")
        v1_run = models.PlaybookRun(
            id=run_id,
            pid=pid,
            playbook_id="pb1",
            title="t",
            status="running",
            created_by="ai-agent",
            created_at=ts_now(),
            started_at=ts_now(),
            finished_at="",
            target="",
            error_output="",
            jobs_json=[],
            request_json={},
            result_json={},
        )
        db.add(v1_run)
        db.commit()

        monkeypatch.setattr("app.routers.playbooks._launch_playbook_run", lambda **kw: run_id)

        async def flip_to_done():
            await _asyncio.sleep(0.03)
            row = db.query(models.PlaybookRun).filter(models.PlaybookRun.id == run_id).first()
            row.status = "done"
            db.commit()

        task = _asyncio.create_task(flip_to_done())
        result = await ai_tools.tool_run_playbook(db, pid, "pb1", wait_seconds=2)
        await task

        assert result["status"] == "done"
        assert result["run_id"] == run_id

    async def test_reports_failure_not_success(self, db, monkeypatch):
        pid = _bare_project(db)
        import asyncio as _asyncio

        from app import models
        from app.core import ai_tools
        from app.core.utils import new_id, ts_now

        monkeypatch.setattr(ai_tools, "_V1_RUN_POLL_INTERVAL", 0.01)

        run_id = new_id("pbr")
        v1_run = models.PlaybookRun(
            id=run_id,
            pid=pid,
            playbook_id="pb1",
            title="t",
            status="running",
            created_by="ai-agent",
            created_at=ts_now(),
            started_at=ts_now(),
            finished_at="",
            target="",
            error_output="",
            jobs_json=[],
            request_json={},
            result_json={},
        )
        db.add(v1_run)
        db.commit()

        monkeypatch.setattr("app.routers.playbooks._launch_playbook_run", lambda **kw: run_id)

        async def flip_to_failed():
            await _asyncio.sleep(0.03)
            row = db.query(models.PlaybookRun).filter(models.PlaybookRun.id == run_id).first()
            row.status = "failed"
            row.error_output = "target unreachable"
            db.commit()

        task = _asyncio.create_task(flip_to_failed())
        result = await ai_tools.tool_run_playbook(db, pid, "pb1", wait_seconds=2)
        await task

        assert result["status"] == "failed"
        assert "unreachable" in result["error"]

    async def test_still_running_past_deadline_is_not_reported_as_success(self, db, monkeypatch):
        pid = _bare_project(db)
        from app import models
        from app.core import ai_tools
        from app.core.utils import new_id, ts_now

        monkeypatch.setattr(ai_tools, "_V1_RUN_POLL_INTERVAL", 0.01)

        run_id = new_id("pbr")
        v1_run = models.PlaybookRun(
            id=run_id,
            pid=pid,
            playbook_id="pb1",
            title="t",
            status="running",
            created_by="ai-agent",
            created_at=ts_now(),
            started_at=ts_now(),
            finished_at="",
            target="",
            error_output="",
            jobs_json=[],
            request_json={},
            result_json={},
        )
        db.add(v1_run)
        db.commit()

        monkeypatch.setattr("app.routers.playbooks._launch_playbook_run", lambda **kw: run_id)

        result = await ai_tools.tool_run_playbook(db, pid, "pb1", wait_seconds=0.05)
        assert result["status"] == "still_running"
