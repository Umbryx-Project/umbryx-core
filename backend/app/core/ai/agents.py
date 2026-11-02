"""AI agent personas — role-scoped assistants over the shared AgentEngine.

An agent is a preset: a mission-focused system prompt plus a tool
allowlist. The tool allowlist is the actual capability boundary — the
OPSEC reviewer literally cannot create findings, the recon analyst
cannot run playbooks — enforced in ToolRegistry.to_openai(allowed=...).

Built-in agents are seeded into the `ai_agents` GlobalSetting on first
read; custom agents can be added alongside (same shape, owner-tracked).
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from ...core.utils import ts_now
from ...models import GlobalSetting
from ..utils import new_id

logger = logging.getLogger(__name__)

AGENTS_KEY = "ai_agents"

_READ_TOOLS = [
    "list_hosts",
    "list_creds",
    "list_findings",
    "list_jobs",
    "get_job_output",
    "get_scope",
    "list_activities",
    "cross_project_briefing",
]

BUILTIN_AGENTS: list[dict] = [
    {
        "id": "field-op",
        "name": "Field Operator",
        "description": "Full-capability engagement assistant: reads state, drafts findings, runs playbooks.",
        "builtin": True,
        "agent_mode": True,
        "system_prompt": (
            "You are an autonomous AI security assistant embedded in Umbryx, "
            "a penetration testing platform.\n"
            "You have tools to read and modify project data, create findings, "
            "run playbooks, and analyze results.\n"
            "Be concise, technical, and focus on actionable security insights.\n"
            "You are operating in an authorized penetration testing environment."
        ),
        "allowed_tools": None,  # full registry
        "suggestions": [
            "Summarize the engagement state and suggest next steps",
            "Which hosts look most exposed? Prioritize targets",
        ],
    },
    {
        "id": "recon-analyst",
        "name": "Recon Analyst",
        "description": "Read-only surface analyst: inventories, exposure ranking, what-to-scan-next.",
        "builtin": True,
        "agent_mode": True,
        "system_prompt": (
            "You are a reconnaissance analyst on an authorized penetration test.\n"
            "You READ the project state (hosts, ports, services, creds coverage, jobs) "
            "and your job is triage: what do we know, what is most exposed, what should "
            "be scanned or validated next and why.\n"
            "You never modify anything — you rank and recommend.\n"
            "Answer with compact, prioritized lists; always ground claims in tool data, "
            "and say explicitly when the data is missing."
        ),
        "allowed_tools": _READ_TOOLS,
        "suggestions": [
            "Rank the 5 most exposed hosts and why",
            "Which subnets have we not covered yet?",
        ],
    },
    {
        "id": "findings-drafter",
        "name": "Findings Drafter",
        "description": "Turns evidence (job output, loot references, cred context) into finding drafts.",
        "builtin": True,
        "agent_mode": True,
        "system_prompt": (
            "You are a findings editor on an authorized penetration test.\n"
            "You read hosts, credentials, jobs and their output, and draft "
            "well-structured findings: title, severity rationale, proof with concrete "
            "evidence quotes, and an actionable recommendation.\n"
            "You may create findings via the tool — but only when the user asked for a "
            "draft or confirmed one; otherwise present the draft text first.\n"
            "Never invent evidence: if proof is thin, mark the draft as needing verification."
        ),
        "allowed_tools": _READ_TOOLS + ["create_finding", "add_host_tag", "create_note"],
        "suggestions": [
            "Draft findings from the last cred validation results",
            "Turn the latest nmap output into a findings backlog",
        ],
    },
    {
        "id": "report-writer",
        "name": "Report Writer",
        "description": "Executive summary and narrative sections from real project state.",
        "builtin": True,
        "agent_mode": True,
        "system_prompt": (
            "You are the reporting writer on an authorized penetration test.\n"
            "You read the full project state and produce client-facing text: executive "
            "summaries, attack narratives, remediation overviews.\n"
            "Style: calm, factual, no hacker slang, no unverified claims; map technical "
            "detail to business risk.\n"
            "You never modify project data."
        ),
        "allowed_tools": _READ_TOOLS,
        "suggestions": [
            "Write an executive summary of this engagement",
            "Draft the remediation overview from open findings",
            "Summarize progress across all my projects, and what to do next",
        ],
    },
    {
        "id": "opsec-reviewer",
        "name": "OPSEC Reviewer",
        "description": "Red-teams your plan: ROE/scope conflicts, noise, detection risk.",
        "builtin": True,
        "agent_mode": True,
        "system_prompt": (
            "You are an OPSEC and rules-of-engagement reviewer on an authorized "
            "penetration test.\n"
            "The user describes a planned action; you check it against the project scope "
            "and ROE context you can read, and critique: scope violations, excessive "
            "noise (loud scans, mass attempts), detection likelihood, evidence hygiene.\n"
            "Verdict format: GO / GO WITH CHANGES / NO-GO, followed by bullet reasons.\n"
            "You never execute or modify anything."
        ),
        "allowed_tools": ["get_scope", "list_activities", "list_hosts", "list_findings"],
        "suggestions": [
            "Plan: cred spray against all 254 hosts in scope — review it",
            "Review my planned AD attack path for OPSEC risks",
        ],
    },
]


def _load_raw(db: Session) -> list[dict]:
    item = db.query(GlobalSetting).filter(GlobalSetting.key == AGENTS_KEY).first()
    return list(item.value) if item and isinstance(item.value, list) else []


def list_agents(db: Session) -> list[dict]:
    """All agents: built-ins (seeded once) + custom."""
    stored = _load_raw(db)
    if not stored:
        stored = [dict(a) for a in BUILTIN_AGENTS]
        item = db.query(GlobalSetting).filter(GlobalSetting.key == AGENTS_KEY).first()
        if item:
            item.value = stored
            from sqlalchemy.orm.attributes import flag_modified

            flag_modified(item, "value")
        else:
            db.add(GlobalSetting(key=AGENTS_KEY, value=stored))
        db.commit()
        return stored
    return stored


def get_agent(db: Session, agent_id: str) -> dict | None:
    return next((a for a in list_agents(db) if a.get("id") == agent_id), None)


def save_custom_agent(db: Session, data: dict, user_id: str) -> dict:
    agents = list_agents(db)
    agent = {
        "id": data.get("id") or new_id("agn"),
        "name": data["name"],
        "description": data.get("description", ""),
        "builtin": False,
        "agent_mode": data.get("agent_mode", True),
        "system_prompt": data["system_prompt"],
        "allowed_tools": data.get("allowed_tools"),  # None = full registry
        "suggestions": data.get("suggestions", []),
        "created_by": user_id,
        "created_at": ts_now(),
    }
    if any(a.get("id") == agent["id"] for a in agents if a.get("builtin")):
        agent["id"] = new_id("agn")  # never shadow a builtin id
    agents.append(agent)
    item = db.query(GlobalSetting).filter(GlobalSetting.key == AGENTS_KEY).first()
    if item:
        item.value = agents
        from sqlalchemy.orm.attributes import flag_modified

        flag_modified(item, "value")
    else:
        db.add(GlobalSetting(key=AGENTS_KEY, value=agents))
    db.commit()
    return agent


def delete_custom_agent(db: Session, agent_id: str) -> bool:
    agents = list_agents(db)
    kept = [a for a in agents if not (a.get("id") == agent_id and not a.get("builtin"))]
    if len(kept) == len(agents):
        return False
    item = db.query(GlobalSetting).filter(GlobalSetting.key == AGENTS_KEY).first()
    item.value = kept
    from sqlalchemy.orm.attributes import flag_modified

    flag_modified(item, "value")
    db.commit()
    return True
