"""
Extensible tool registry for AI agent mode.

Tools self-register with risk levels so the agent engine can enforce safety:
  - read:   auto-approved, no confirmation needed
  - write:  requires user confirmation (configurable)
  - critical: blocked by default, requires explicit allow

Usage::

    @tool_registry.register(
        "scan_network",
        risk=RiskLevel.READ,
        description="Scan a network range",
        params={"cidr": {"type": "string", "description": "CIDR range"}},
        required=["cidr"],
    )
    def scan_network(db, pid, cidr):
        ...
"""

from __future__ import annotations

import asyncio
import enum
import inspect
import logging
from collections.abc import Callable
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


class RiskLevel(str, enum.Enum):
    READ = "read"
    WRITE = "write"
    CRITICAL = "critical"


@dataclass
class ToolDef:
    """Definition of a tool callable by the AI agent."""

    name: str
    description: str
    risk: RiskLevel = RiskLevel.READ
    params: dict = field(default_factory=dict)
    required: list[str] = field(default_factory=list)
    handler: Callable | None = None
    module_id: str = ""  # which module registered this tool
    # The project RBAC permission (see core/permissions.py) the calling
    # user must hold for this action — the same one its direct REST
    # equivalent checks (e.g. create_finding <-> POST /findings both
    # require "findings.create"; list_hosts <-> GET /hosts both require
    # "hosts.read"). A tool without this set would let *any* project
    # member reach it through chat regardless of role — the
    # send_message/stream_message endpoints only check "findings.read"
    # as a stand-in for "is a member of this project" and rely entirely
    # on this field for anything more specific, read or write. Leave
    # unset only for a tool that genuinely has no single project's
    # permission to check (cross_project_briefing iterates every project
    # the caller is a member of instead of reading `pid`).
    required_permission: str | None = None

    def to_openai(self) -> dict:
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": {
                    "type": "object",
                    "properties": self.params,
                    "required": self.required,
                },
            },
        }

    def to_anthropic(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": {
                "type": "object",
                "properties": self.params,
                "required": self.required,
            },
        }

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "risk": self.risk.value,
            "params": self.params,
            "required": self.required,
            "module_id": self.module_id,
            "required_permission": self.required_permission,
        }


class ToolRegistry:
    """Thread-safe registry for AI tools."""

    def __init__(self):
        self._tools: dict[str, ToolDef] = {}

    def register(
        self,
        name: str,
        description: str = "",
        risk: RiskLevel = RiskLevel.READ,
        params: dict | None = None,
        required: list[str] | None = None,
        handler: Callable | None = None,
        module_id: str = "core",
        required_permission: str | None = None,
    ):
        """Register a tool. Can be used as decorator or direct call."""

        def decorator(fn: Callable):
            self._tools[name] = ToolDef(
                name=name,
                description=description or fn.__doc__ or "",
                risk=risk,
                params=params or {},
                required=required or [],
                handler=fn,
                module_id=module_id,
                required_permission=required_permission,
            )
            logger.debug("AI tool registered: %s (risk=%s)", name, risk.value)
            return fn

        if handler is not None:
            decorator(handler)
            return handler
        return decorator

    def unregister(self, name: str) -> bool:
        return self._tools.pop(name, None) is not None

    def get(self, name: str) -> ToolDef | None:
        return self._tools.get(name)

    def list_all(self) -> list[ToolDef]:
        return list(self._tools.values())

    def list_names(self) -> list[str]:
        return sorted(self._tools.keys())

    def to_openai(
        self, include_critical: bool = False, allowed: list[str] | None = None
    ) -> list[dict]:
        """OpenAI tool schemas.

        `allowed` restricts the agent to a subset of tool names — the
        per-agent capability boundary (an OPSEC reviewer must not create
        findings; a recon analyst must not run playbooks). None = all.
        """
        return [
            t.to_openai()
            for t in self._tools.values()
            if (include_critical or t.risk != RiskLevel.CRITICAL)
            and (allowed is None or t.name in allowed)
        ]

    def to_dict_list(self) -> list[dict]:
        return [t.to_dict() for t in self._tools.values()]

    async def execute(
        self, db: Session, pid: str, name: str, args: dict, user_id: str | None = None
    ) -> dict:
        td = self._tools.get(name)
        if td is None or td.handler is None:
            return {"error": f"Unknown tool: {name}"}
        # Interactive chat calls always carry a user_id (see ai_v2.py); the
        # automations executor calls this without one, since an automation
        # was already authorized against its creator's role when it was
        # created/updated (playbooks.create/update) or manually triggered
        # (playbooks.run) — re-checking here would just re-derive the same
        # answer against the wrong actor (there's no "current user" once a
        # schedule/event fires it later). Only gate the interactive path.
        user = None
        if user_id:
            from ...models import User as _User

            user = db.query(_User).filter(_User.id == user_id).first()
        if user_id and td.required_permission:
            from ..access import user_has_permission

            if not user or not user_has_permission(db, pid, user, td.required_permission):
                logger.info(
                    "[tool_registry] denied %s for user=%s pid=%s (missing %s)",
                    name,
                    user_id,
                    pid,
                    td.required_permission,
                )
                return {
                    "error": (
                        f"Insufficient permissions: '{name}' requires "
                        f"'{td.required_permission}', which your role on this "
                        f"project does not grant."
                    )
                }
        try:
            call_kwargs = dict(args)
            # Most tools don't need the caller's identity — only pass it to
            # ones that actually declare the parameter (e.g. a cross-project
            # briefing), so every other handler's signature stays untouched.
            if "user_id" in inspect.signature(td.handler).parameters:
                call_kwargs["user_id"] = user_id
            # Attribution: actions performed BY the agent ON BEHALF OF the
            # chatting user are labeled "ai:<username>" — handlers that
            # declare actor_label stamp it onto the entities they create
            # (jobs.created_by, finding.source, note tags).
            if "actor_label" in inspect.signature(td.handler).parameters:
                call_kwargs["actor_label"] = (
                    f"ai:{user.username}" if user and getattr(user, "username", "") else "ai:automation"
                )
            result = td.handler(db=db, pid=pid, **call_kwargs)
            if asyncio.iscoroutine(result):
                result = await result
            return result
        except Exception as e:
            logger.warning("[tool_registry] tool %s error: %s", name, e)
            return {"error": str(e)}


tool_registry = ToolRegistry()


def _register_builtin_tools():
    """Import existing tools from ai_tools.py and register them."""
    from ..ai_tools import (
        TOOL_DEFS,
        tool_add_host_tag,
        tool_create_finding,
        tool_create_note,
        tool_cross_project_briefing,
        tool_get_host,
        tool_get_job_output,
        tool_get_scope,
        tool_list_activities,
        tool_list_creds,
        tool_list_findings,
        tool_list_hosts,
        tool_list_jobs,
        tool_run_command,
        tool_run_playbook,
        tool_run_scan,
        tool_tool_guide,
    )

    _handler_map = {
        "list_hosts": tool_list_hosts,
        "get_host": tool_get_host,
        "list_creds": tool_list_creds,
        "list_findings": tool_list_findings,
        "create_finding": tool_create_finding,
        "add_host_tag": tool_add_host_tag,
        "list_jobs": tool_list_jobs,
        "get_job_output": tool_get_job_output,
        "get_scope": tool_get_scope,
        "cross_project_briefing": tool_cross_project_briefing,
        "list_activities": tool_list_activities,
        "run_playbook": tool_run_playbook,
        "create_note": tool_create_note,
        "run_scan": tool_run_scan,
        "run_command": tool_run_command,
        "tool_guide": tool_tool_guide,
    }

    _risk_map = {
        "list_hosts": RiskLevel.READ,
        "get_host": RiskLevel.READ,
        "list_creds": RiskLevel.READ,
        "list_findings": RiskLevel.READ,
        "create_finding": RiskLevel.WRITE,
        "add_host_tag": RiskLevel.WRITE,
        "list_jobs": RiskLevel.READ,
        "get_job_output": RiskLevel.READ,
        "get_scope": RiskLevel.READ,
        "cross_project_briefing": RiskLevel.READ,
        "list_activities": RiskLevel.READ,
        "run_playbook": RiskLevel.CRITICAL,
        "create_note": RiskLevel.WRITE,
        # WRITE (not CRITICAL) on purpose: the model must SEE the tool and
        # offer to run scans — execution goes through the one-click chat
        # confirmation (require_confirmation_writes) + RBAC
        # (command_outputs.create), same bar as the scans UI.
        "run_scan": RiskLevel.WRITE,
        "run_command": RiskLevel.WRITE,
        "tool_guide": RiskLevel.READ,
    }

    # Every tool must require exactly the permission its direct REST
    # equivalent checks (verified against each router's check_pid_access
    # call, not guessed) — otherwise chat is a side door around a role's
    # granted permissions. This applies to reads too: the chat endpoint's
    # own "findings.read" only proves project membership, not that this
    # role can read *this* resource — e.g. reviewer has findings.read but
    # not hosts.read/credentials.read/command_outputs.read on the direct
    # REST routes (routers/hosts.py, creds.py, jobs.py, activities.py),
    # and auditor lacks credentials.read there too; both must be denied
    # list_hosts/list_creds/list_jobs/list_activities/get_job_output
    # through chat exactly as they already are on those routes.
    # cross_project_briefing is the one deliberate exception: it doesn't
    # read *this* project via `pid` at all — it iterates every project
    # get_user_member_pids() returns for the caller, which is itself the
    # correct per-project membership boundary, so there's no single
    # project permission to check here.
    _permission_map = {
        "list_hosts": "hosts.read",
        "get_host": "hosts.read",
        "list_creds": "credentials.read",
        "list_findings": "findings.read",
        "create_finding": "findings.create",
        "add_host_tag": "hosts.update",
        "list_jobs": "command_outputs.read",
        "get_job_output": "command_outputs.read",
        "get_scope": "scopes.read",
        "list_activities": "command_outputs.read",
        "run_playbook": "command_outputs.create",
        "run_scan": "command_outputs.create",
        "run_command": "command_outputs.create",
        "create_note": "notes.create",
    }

    for td in TOOL_DEFS:
        name = td["name"]
        handler = _handler_map.get(name)
        if handler:
            tool_registry.register(
                name=name,
                description=td["description"],
                risk=_risk_map.get(name, RiskLevel.READ),
                params=td.get("params", {}),
                required=td.get("required", []),
                handler=handler,
                required_permission=_permission_map.get(name),
            )


_register_builtin_tools()
