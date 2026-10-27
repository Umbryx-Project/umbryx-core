from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import yaml


@dataclass
class StepDef:
    id: str
    type: str = "action"
    action: str = ""
    params: dict = field(default_factory=dict)
    on_error: str = "stop"
    retry_count: int = 0
    retry_delay: float = 1.0
    timeout: float | None = None
    then: list[StepDef] = field(default_factory=list)
    else_: list[StepDef] = field(default_factory=list)
    condition: dict | None = None
    duration: float = 0.0
    loop_over: str = ""
    loop_var: str = "item"
    loop_body: list[StepDef] = field(default_factory=list)
    playbook_id: str = ""


@dataclass
class TriggerDef:
    type: str = "manual"
    event: str = ""
    cron: str = ""
    playbook_id: str = ""
    debounce_ms: int = 0
    rate_limit_per_hour: int = 0


@dataclass
class PlaybookDefinition:
    triggers: list[TriggerDef] = field(default_factory=list)
    conditions: list[dict] = field(default_factory=list)
    steps: list[StepDef] = field(default_factory=list)
    settings: dict = field(default_factory=dict)

    @property
    def timeout(self) -> float:
        return float(self.settings.get("timeout", 300))

    @property
    def max_concurrent(self) -> int:
        return int(self.settings.get("max_concurrent", 1))

    @property
    def on_step_error(self) -> str:
        return self.settings.get("on_step_error", "stop")

    def to_dict(self) -> dict:
        return {
            "triggers": [
                {
                    "type": t.type,
                    "event": t.event,
                    "cron": t.cron,
                    "playbook_id": t.playbook_id,
                    "debounce_ms": t.debounce_ms,
                    "rate_limit_per_hour": t.rate_limit_per_hour,
                }
                for t in self.triggers
            ],
            "conditions": self.conditions,
            "steps": [_step_to_dict(s) for s in self.steps],
            "settings": self.settings,
        }

    @staticmethod
    def from_dict(d: dict) -> PlaybookDefinition:
        triggers = [
            TriggerDef(
                type=t.get("type", "manual"),
                event=t.get("event", ""),
                cron=t.get("cron", ""),
                playbook_id=t.get("playbook_id", ""),
                debounce_ms=int(t.get("debounce_ms", 0)),
                rate_limit_per_hour=int(t.get("rate_limit_per_hour", 0)),
            )
            for t in d.get("triggers", [])
        ]
        conditions = d.get("conditions", [])
        steps = [_parse_step(s) for s in d.get("steps", [])]
        settings = d.get("settings", {})
        return PlaybookDefinition(
            triggers=triggers,
            conditions=conditions,
            steps=steps,
            settings=settings,
        )


def _parse_step(raw: dict) -> StepDef:
    return StepDef(
        id=raw.get("id", ""),
        type=raw.get("type", "action"),
        action=raw.get("action", ""),
        params=raw.get("params", {}),
        on_error=raw.get("on_error", "stop"),
        retry_count=(
            int(raw.get("retry", {}).get("count", 0))
            if isinstance(raw.get("retry"), dict)
            else int(raw.get("retry_count", 0))
        ),
        retry_delay=(
            float(raw.get("retry", {}).get("delay", 1.0))
            if isinstance(raw.get("retry"), dict)
            else float(raw.get("retry_delay", 1.0))
        ),
        timeout=raw.get("timeout"),
        then=[_parse_step(s) for s in raw.get("then", [])],
        else_=[_parse_step(s) for s in raw.get("else", [])],
        condition=raw.get("condition"),
        duration=float(raw.get("duration", 0)),
        loop_over=raw.get("loop_over", ""),
        loop_var=raw.get("loop_var", "item"),
        loop_body=[_parse_step(s) for s in raw.get("loop_body", [])],
        playbook_id=raw.get("playbook_id", ""),
    )


def _step_to_dict(s: StepDef) -> dict:
    d: dict[str, Any] = {"id": s.id, "type": s.type}
    if s.type == "action":
        d["action"] = s.action
        d["params"] = s.params
        d["on_error"] = s.on_error
        if s.retry_count:
            d["retry"] = {"count": s.retry_count, "delay": s.retry_delay}
    elif s.type == "delay":
        d["duration"] = s.duration
    elif s.type == "if":
        d["condition"] = s.condition
        d["then"] = [_step_to_dict(x) for x in s.then]
        d["else"] = [_step_to_dict(x) for x in s.else_]
    elif s.type == "loop":
        d["loop_over"] = s.loop_over
        d["loop_var"] = s.loop_var
        d["loop_body"] = [_step_to_dict(x) for x in s.loop_body]
    elif s.type == "call":
        d["playbook_id"] = s.playbook_id
    if s.timeout is not None:
        d["timeout"] = s.timeout
    return d


def parse_definition(raw: str | dict) -> PlaybookDefinition:
    if isinstance(raw, str):
        d = yaml.safe_load(raw)
        if d is None:
            d = {}
    else:
        d = raw

    if not isinstance(d, dict):
        raise ValueError("Playbook definition must be a mapping")

    return PlaybookDefinition.from_dict(d)
