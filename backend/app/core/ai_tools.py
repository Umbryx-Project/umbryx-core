"""
AI tool implementations — callable by the LLM agent.
Each async function takes (db, pid, **kwargs).
"""

import asyncio
import logging

from sqlalchemy.orm import Session

from .. import models
from .utils import new_id, ts_now

logger = logging.getLogger(__name__)


# ── Tool implementations ──────────────────────────────────────────────


def tool_list_hosts(db: Session, pid: str, query: str = "", tags=None, status: str = None):
    q = db.query(models.Host).filter(models.Host.pid == pid)
    if query:
        q = q.filter(
            (models.Host.ip.ilike(f"%{query}%")) | (models.Host.hostname.ilike(f"%{query}%"))
        )
    if status:
        q = q.filter(models.Host.status == status)
    hosts = q.all()
    if tags:
        if isinstance(tags, str):
            tags = [tags]
        hosts = [h for h in hosts if any(t in (h.tags or []) for t in tags)]
    result = []
    for h in hosts:
        result.append(
            {
                "id": h.id,
                "ip": h.ip,
                "hostname": h.hostname,
                "os": h.os,
                "status": h.status,
                "ports": (h.ports or [])[:5],
                "tags": h.tags or [],
                "is_attacker": h.is_attacker,
            }
        )
    return result


def tool_get_host(db: Session, pid: str, host_id: str):
    h = db.query(models.Host).filter(models.Host.id == host_id, models.Host.pid == pid).first()
    if not h:
        return {"error": "Host not found"}
    linked_notes = (
        db.query(models.Note)
        .filter(models.Note.host_id == host_id, models.Note.deleted_at.is_(None))
        .order_by(models.Note.ts.desc())
        .all()
    )
    return {
        "id": h.id,
        "ip": h.ip,
        "ips": h.ips or [],
        "hostname": h.hostname,
        "os": h.os,
        "status": h.status,
        "ports": h.ports or [],
        "services": h.services or [],
        "tags": h.tags or [],
        "notes": [{"title": n.title, "content": n.content} for n in linked_notes],
        "domain": h.domain,
        "role": h.role,
        "is_attacker": h.is_attacker,
        "import_source": h.import_source,
    }


def tool_list_creds(db: Session, pid: str, query: str = "", cred_type: str = None):
    q = db.query(models.Cred).filter(models.Cred.pid == pid)
    if cred_type:
        q = q.filter(models.Cred.type == cred_type)
    creds = q.all()
    if query:
        creds = [
            c
            for c in creds
            if query.lower() in c.username.lower() or query.lower() in (c.domain or "").lower()
        ]
    result = []
    for c in creds:
        result.append(
            {
                "id": c.id,
                "username": c.username,
                "domain": c.domain,
                "type": c.type,
                "service": c.service,
                "host": c.host,
                "tags": c.tags or [],
                "host_ids": c.host_ids or [],
            }
        )
    return result


def tool_list_findings(db: Session, pid: str, severity: str = None, status: str = None):
    q = db.query(models.Finding).filter(models.Finding.pid == pid)
    if severity:
        q = q.filter(models.Finding.severity == severity)
    if status:
        q = q.filter(models.Finding.status == status)
    findings = q.all()
    return [
        {
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "status": f.status,
            "host_id": f.host_id,
            "cve": f.cve,
            "cvss": f.cvss,
            "description": f.description[:200] if f.description else "",
        }
        for f in findings
    ]


def tool_create_finding(
    db: Session,
    pid: str,
    title: str,
    severity: str,
    description: str = "",
    recommendation: str = "",
    host_id: str = None,
    actor_label: str = "ai",
):
    now = ts_now()
    finding = models.Finding(
        id=new_id("f"),
        pid=pid,
        title=title,
        severity=severity,
        description=description,
        recommendation=recommendation,
        host_id=host_id,
        status="open",
        ts=now,
        cvss="",
        cve="",
        proof="",
        source=actor_label,  # "ai:<username>" — visible in the findings list
    )
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return {
        "id": finding.id,
        "title": finding.title,
        "severity": finding.severity,
        "status": finding.status,
        "host_id": finding.host_id,
    }


def tool_add_host_tag(db: Session, pid: str, host_id: str, tag: str):
    host = db.query(models.Host).filter(models.Host.id == host_id, models.Host.pid == pid).first()
    if not host:
        return {"error": "Host not found"}
    tags = list(host.tags or [])
    if tag not in tags:
        tags.append(tag)
        host.tags = tags
        db.commit()
        db.refresh(host)
    return {
        "id": host.id,
        "ip": host.ip,
        "hostname": host.hostname,
        "tags": host.tags or [],
    }


def tool_list_jobs(db: Session, pid: str, limit: int = 10, status: str = None):
    q = db.query(models.Job).filter(models.Job.pid == pid)
    if status:
        q = q.filter(models.Job.status == status)
    jobs = q.order_by(models.Job.created_at.desc()).limit(limit).all()
    return [
        {
            "id": j.id,
            "title": j.title,
            "status": j.status,
            "connector_key": j.connector_key,
            "operation": j.operation,
            "created_at": j.created_at,
            "finished_at": j.finished_at,
        }
        for j in jobs
    ]


def tool_get_job_output(db: Session, pid: str, job_id: str):
    job = db.query(models.Job).filter(models.Job.id == job_id, models.Job.pid == pid).first()
    if not job:
        return {"error": "Job not found"}
    output = (job.output or "")[:3000]
    return {
        "id": job.id,
        "title": job.title,
        "status": job.status,
        "output": output,
        "output_truncated": len(job.output or "") > 3000,
        "result_json": job.result_json or {},
    }


def tool_get_scope(db: Session, pid: str):
    scopes = db.query(models.Scope).filter(models.Scope.pid == pid).all()
    return [
        {
            "id": s.id,
            "value": s.value,
            "scope_type": s.scope_type,
            "in_scope": s.in_scope,
            "description": s.description,
        }
        for s in scopes
    ]


def tool_cross_project_briefing(
    db: Session, pid: str, user_id: str = None, include_archived: bool = False
):
    """Read-only snapshot across every project the caller can see — not
    just the one this chat is scoped to. Lets the model answer "which
    project is closest to done", "where are hypotheses still untested",
    and "what should we do next" without the operator switching projects
    and asking the same question N times.
    """
    from .access import get_user_member_pids

    user = db.query(models.User).filter(models.User.id == user_id).first() if user_id else None
    if not user:
        return {"error": "No authenticated user context available for a cross-project briefing"}

    member_pids = get_user_member_pids(db, user)
    if not member_pids:
        return {"projects": []}

    q = db.query(models.Project).filter(models.Project.id.in_(member_pids))
    if not include_archived:
        q = q.filter(models.Project.archived_at.is_(None))

    briefing = []
    for p in q.all():
        obj_total = db.query(models.Objective).filter(models.Objective.pid == p.id).count()
        obj_done = (
            db.query(models.Objective)
            .filter(
                models.Objective.pid == p.id, models.Objective.status.in_(["captured", "submitted"])
            )
            .count()
        )

        steps_total = db.query(models.AttackStep).filter(models.AttackStep.pid == p.id).count()
        steps_untested = (
            db.query(models.AttackStep)
            .filter(
                models.AttackStep.pid == p.id,
                models.AttackStep.node_status.in_(["hypothetical", "planned"]),
            )
            .count()
        )
        steps_verified = (
            db.query(models.AttackStep)
            .filter(models.AttackStep.pid == p.id, models.AttackStep.node_status == "verified")
            .count()
        )

        open_findings = (
            db.query(models.Finding)
            .filter(models.Finding.pid == p.id, models.Finding.status == "open")
            .count()
        )

        last_event = (
            db.query(models.TimelineEvent)
            .filter(models.TimelineEvent.pid == p.id)
            .order_by(models.TimelineEvent.ts.desc())
            .first()
        )

        briefing.append(
            {
                "project_id": p.id,
                "name": p.name,
                "status": p.status,
                "objectives_total": obj_total,
                "objectives_done": obj_done,
                "attack_steps_total": steps_total,
                "attack_steps_untested_hypotheses": steps_untested,
                "attack_steps_verified": steps_verified,
                "open_findings": open_findings,
                "last_activity_ts": last_event.ts if last_event else None,
            }
        )

    return {"projects": briefing}


def tool_list_activities(db: Session, pid: str, host_id: str = None, limit: int = 20):
    q = db.query(models.HostActivity).filter(models.HostActivity.pid == pid)
    if host_id:
        q = q.filter(models.HostActivity.host_id == host_id)
    activities = q.order_by(models.HostActivity.ts.desc()).limit(limit).all()
    return [
        {
            "id": a.id,
            "host_id": a.host_id,
            "title": a.title,
            "activity_type": a.activity_type,
            "summary": a.summary,
            "status": a.status,
            "ts": a.ts,
        }
        for a in activities
    ]


_V1_TERMINAL_STATUSES = {"done", "failed", "cancelled"}
_V1_RUN_POLL_INTERVAL = 2.0
_V1_RUN_MAX_WAIT_DEFAULT = 120.0
_V1_RUN_MAX_WAIT_CAP = 600.0


async def tool_run_playbook(
    db: Session,
    pid: str,
    playbook_id: str,
    target: str = "",
    username: str = "",
    password: str = "",
    domain: str = "",
    hash: str = "",
    wait_seconds: float = _V1_RUN_MAX_WAIT_DEFAULT,
    actor_label: str = "ai",
):
    """Launch a v1 tool-chain playbook and wait for it to actually finish
    before reporting a result — launching alone used to be reported back
    as {"status": "launched"} immediately, which the automation engine's
    executor then wrapped as step status "success" the instant the v1 run
    was merely *queued*, not once it had actually done anything. That's
    the "accepted, not confirmed" failure mode called out for
    automation-triggered external actions: a step must reflect the real
    outcome of what it invoked, not just that the invocation was sent
    (2026-08-19). Bounded by wait_seconds (capped) so a stuck/long-running
    v1 playbook can't hang the calling automation step forever — a
    still-running run past the cap is reported as such, not silently
    treated as success.
    """
    from ..routers.playbooks import _launch_playbook_run

    body_dict = {
        "target": target,
        "username": username,
        "password": password,
        "domain": domain,
        "hash": hash,
    }
    run_id = _launch_playbook_run(
        pid=pid, playbook_id=playbook_id, body_dict=body_dict, created_by=actor_label
    )
    if not run_id:
        return {"error": "Failed to launch playbook", "run_id": None}

    deadline = min(max(wait_seconds, 0.0), _V1_RUN_MAX_WAIT_CAP)
    elapsed = 0.0
    while elapsed < deadline:
        await asyncio.sleep(_V1_RUN_POLL_INTERVAL)
        elapsed += _V1_RUN_POLL_INTERVAL
        db.expire_all()
        run = db.query(models.PlaybookRun).filter(models.PlaybookRun.id == run_id).first()
        if run and run.status in _V1_TERMINAL_STATUSES:
            result = {"run_id": run_id, "status": run.status}
            if run.status == "failed":
                result["error"] = run.error_output or "Playbook run failed"
            return result

    return {
        "run_id": run_id,
        "status": "still_running",
        "note": f"Playbook did not finish within {deadline:.0f}s — check run {run_id} separately",
    }


def tool_run_scan(
    db: Session,
    pid: str,
    tool: str,
    target: str,
    flags: str = "",
    target_id: str = "",
    timeout_seconds: int = 300,
    intensity_profile: str = "",
    actor_label: str = "ai",
):
    """Queue a scan as a background Job — the agent gets the job_id instantly
    and polls get_job_output; the scan itself runs on the attacker machine
    through the standard queued-job pipeline (same as playbooks/scans UI)."""
    tool = (tool or "").lower().strip()
    from .job_runner import schedule_job_run, supports_queued_execution

    if not supports_queued_execution(tool, "scan"):
        return {
            "error": f"unsupported scan tool '{tool}' (expected nmap/nuclei/netexec/httpx/ffuf)"
        }
    target = (target or "").strip()
    if not target:
        return {"error": "target is required (IP, CIDR or hostname)"}

    from .job_tracker import queue_job

    job = queue_job(
        db,
        pid,
        tool,
        f"[AI] {tool} scan",
        target=target,
        created_by=actor_label,
        connector_key=tool,
        operation="scan",
        request_json={
            "target": target,
            "flags": flags or "",
            "target_id": target_id or "",
            "timeout_seconds": int(timeout_seconds or 300),
            "intensity_profile": intensity_profile or "",
        },
    )
    schedule_job_run(job.id, pid=pid)
    return {
        "job_id": job.id,
        "status": "queued",
        "message": (
            "Scan queued — poll get_job_output with this job_id (status "
            "queued/running/done). On completion results are written into the "
            "project automatically (hosts/ports/services, findings for nuclei, "
            "creds for netexec)."
        ),
    }


async def tool_run_command(
    db: Session,
    pid: str,
    command: str,
    target_id: str = "",
    timeout_seconds: int = 90,
    activity_type: str = "recon",
    actor_label: str = "ai",
):
    """Run an arbitrary command on the project's attacker machine through
    the attacker-exec pipeline (transport fallback, HostActivity + Job,
    audit). For recipes the model doesn't remember — it should consult
    tool_guide first."""
    command = (command or "").strip()
    if not command:
        return {"error": "command is required"}
    if any(bad in command for bad in ("rm -rf /", "mkfs", "dd if=/dev/")):
        return {"error": "command rejected by safety check"}
    timeout_seconds = max(10, min(int(timeout_seconds or 90), 180))

    from fastapi import HTTPException

    from ..routers.attacker_exec import AttackerExecBody, run_attacker_exec_core

    body = AttackerExecBody(
        command=command,
        snippet_title=f"[AI] {command.splitlines()[0][:70]}",
        target_id=target_id or None,
        timeout_seconds=timeout_seconds,
        activity_type=activity_type or "recon",
    )
    try:
        r = await run_attacker_exec_core(db, pid, body, actor_label)
    except HTTPException as e:
        return {"error": f"exec failed: {e.detail}", "status_code": e.status_code}
    return {
        "ok": r.get("ok", False),
        "exit_code": r.get("exit_code", -1),
        "stdout": (r.get("stdout") or "")[:4000],
        "stderr": (r.get("stderr") or "")[:1000],
        "job_id": r.get("job_id"),
        "note": (
            "Output recorded in HostActivity and the Jobs feed "
            "(attributed " + actor_label + ")."
        ),
    }


def tool_tool_guide(db: Session, pid: str, query: str):
    """Retrieve curated tool recipes (exact commands) for a task."""
    from .ai.tool_guides import search_tool_guides

    matches = search_tool_guides(query)
    if not matches:
        return {
            "results": [],
            "hint": (
                "No guide matched. Ask the user to clarify the task, or "
                "build the command from first principles and run it via "
                "run_command (with confirmation)."
            ),
        }
    return {
        "results": [
            {
                "topic": g["topic"],
                "notes": g["notes"],
                "commands": g["commands"],
            }
            for g in matches
        ],
        "hint": "Substitute {placeholders} with real values before running via run_command.",
    }


def tool_create_note(
    db: Session,
    pid: str,
    title: str,
    content: str,
    phase: str = "recon",
    tags=None,
    actor_label: str = "ai",
):
    now = ts_now()
    note = models.Note(
        id=new_id("n"),
        pid=pid,
        title=title,
        content=content,
        phase=phase,
        tags=[*(tags or []), actor_label],  # "ai:<username>" chip in the notes list
        ts=now,
        starred=False,
        version=0,
    )
    db.add(note)
    db.commit()
    db.refresh(note)
    return {
        "id": note.id,
        "pid": note.pid,
        "title": note.title,
        "phase": note.phase,
        "tags": note.tags or [],
        "ts": note.ts,
    }


# ── Tool definitions ──────────────────────────────────────────────────

TOOL_DEFS = [
    {
        "name": "list_hosts",
        "description": "List hosts in the project. Filter by IP/hostname query, tags, or status.",
        "params": {
            "query": {"type": "string", "description": "Filter by IP or hostname (partial match)"},
            "tags": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Filter hosts that have any of these tags",
            },
            "status": {
                "type": "string",
                "description": "Filter by host status (e.g. compromised, unknown, alive)",
            },
        },
        "required": [],
    },
    {
        "name": "get_host",
        "description": "Get full details of a host including ports, services, notes, tags.",
        "params": {
            "host_id": {"type": "string", "description": "Host ID"},
        },
        "required": ["host_id"],
    },
    {
        "name": "list_creds",
        "description": "List credentials in the project (secrets are not included).",
        "params": {
            "query": {"type": "string", "description": "Filter by username or domain"},
            "cred_type": {
                "type": "string",
                "description": "Filter by type: plain, hash, ntlm, kerberos",
            },
        },
        "required": [],
    },
    {
        "name": "list_findings",
        "description": "List security findings/vulnerabilities in the project.",
        "params": {
            "severity": {
                "type": "string",
                "description": "Filter by severity: critical, high, medium, low, info",
            },
            "status": {
                "type": "string",
                "description": "Filter by status: open, resolved, accepted",
            },
        },
        "required": [],
    },
    {
        "name": "create_finding",
        "description": "Create a new security finding/vulnerability.",
        "params": {
            "title": {"type": "string", "description": "Finding title"},
            "severity": {
                "type": "string",
                "description": "Severity: critical, high, medium, low, info",
            },
            "description": {"type": "string", "description": "Finding description"},
            "recommendation": {"type": "string", "description": "Remediation recommendation"},
            "host_id": {"type": "string", "description": "Associated host ID (optional)"},
        },
        "required": ["title", "severity"],
    },
    {
        "name": "add_host_tag",
        "description": "Add a tag to a host.",
        "params": {
            "host_id": {"type": "string", "description": "Host ID"},
            "tag": {"type": "string", "description": "Tag to add"},
        },
        "required": ["host_id", "tag"],
    },
    {
        "name": "list_jobs",
        "description": "List recent jobs/scans in the project.",
        "params": {
            "limit": {"type": "integer", "description": "Max results (default 10)"},
            "status": {
                "type": "string",
                "description": "Filter by status: queued, running, done, failed",
            },
        },
        "required": [],
    },
    {
        "name": "get_job_output",
        "description": "Get the output of a job/scan (truncated to 3000 chars).",
        "params": {
            "job_id": {"type": "string", "description": "Job ID"},
        },
        "required": ["job_id"],
    },
    {
        "name": "get_scope",
        "description": "Get the scope/target list for the project.",
        "params": {},
        "required": [],
    },
    {
        "name": "cross_project_briefing",
        "description": (
            "Get a read-only snapshot across every project the current user can see (not just "
            "the current one): objectives progress, attack-path steps still hypothetical/planned "
            "(untested) vs verified, open findings count, and last activity timestamp per project. "
            "Use this to answer questions like 'which project is closest to done', 'which "
            "hypotheses haven't we tested yet', or 'give me a summary/suggestions across all my "
            "projects'."
        ),
        "params": {
            "include_archived": {
                "type": "boolean",
                "description": "Include archived projects (default false)",
            },
        },
        "required": [],
    },
    {
        "name": "list_activities",
        "description": "List host activities/events in the project.",
        "params": {
            "host_id": {"type": "string", "description": "Filter by host ID"},
            "limit": {"type": "integer", "description": "Max results (default 20)"},
        },
        "required": [],
    },
    {
        "name": "run_playbook",
        "description": "Launch a playbook run asynchronously.",
        "params": {
            "playbook_id": {"type": "string", "description": "Playbook ID to run"},
            "target": {"type": "string", "description": "Target IP/host"},
            "username": {"type": "string", "description": "Username for auth"},
            "password": {"type": "string", "description": "Password for auth"},
            "domain": {"type": "string", "description": "Domain for auth"},
            "hash": {"type": "string", "description": "NTLM hash for auth"},
        },
        "required": ["playbook_id"],
    },
    {
        "name": "create_note",
        "description": "Create a note in the project.",
        "params": {
            "title": {"type": "string", "description": "Note title"},
            "content": {"type": "string", "description": "Note content (markdown)"},
            "phase": {
                "type": "string",
                "description": "Phase: recon, exploitation, post-exploitation, reporting",
            },
            "tags": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Tags for the note",
            },
        },
        "required": ["title", "content"],
    },
    {
        "name": "run_scan",
        "description": (
            "Queue a network scan (nmap/nuclei/netexec/httpx/ffuf) to run on the "
            "project's attacker machine. Runs ASYNCHRONOUSLY as a Job — returns "
            "job_id immediately; poll get_job_output(job_id) for progress/results. "
            "Results also land in the project (hosts/findings/creds) automatically."
        ),
        "params": {
            "tool": {
                "type": "string",
                "enum": ["nmap", "nuclei", "netexec", "httpx", "ffuf"],
                "description": "Scan tool to run",
            },
            "target": {"type": "string", "description": "Target IP, CIDR or hostname"},
            "flags": {"type": "string", "description": "Extra tool flags (optional)"},
            "target_id": {
                "type": "string",
                "description": "Attacker target ID (optional — auto-selected when empty)",
            },
            "timeout_seconds": {
                "type": "integer",
                "description": "Scan timeout in seconds (default 300)",
            },
        },
        "required": ["tool", "target"],
    },
    {
        "name": "run_command",
        "description": (
            "Run an arbitrary command on the project's attacker machine "
            "(dig, impacket-*, netexec extras, anything not covered by "
            "run_scan). Synchronous with output returned directly; "
            "recorded as HostActivity+Job attributed ai:<username>. "
            "Consult tool_guide first if unsure about syntax/flags."
        ),
        "params": {
            "command": {"type": "string", "description": "Shell command to execute"},
            "target_id": {"type": "string", "description": "Attacker target ID (optional)"},
            "timeout_seconds": {"type": "integer", "description": "Timeout (10-180s, default 90)"},
            "activity_type": {"type": "string", "description": "recon | exploitation | postex"},
        },
        "required": ["command"],
    },
    {
        "name": "tool_guide",
        "description": (
            "Look up curated recipes (exact commands) for offensive tasks: "
            "dns recon, zone transfer (AXFR), smb enum, kerberoast, "
            "spraying, ldap, web, tunnels... Call this BEFORE inventing "
            "flags or when the user asks for a technique by name."
        ),
        "params": {
            "query": {"type": "string", "description": "Task or technique, e.g. 'dns zone transfer'"},
        },
        "required": ["query"],
    },
]


def _tool_def_to_openai(td: dict) -> dict:
    """Convert internal tool def to OpenAI function tool format."""
    return {
        "type": "function",
        "function": {
            "name": td["name"],
            "description": td["description"],
            "parameters": {
                "type": "object",
                "properties": td.get("params", {}),
                "required": td.get("required", []),
            },
        },
    }


def _tool_def_to_anthropic(td: dict) -> dict:
    """Convert internal tool def to Anthropic tool format."""
    return {
        "name": td["name"],
        "description": td["description"],
        "input_schema": {
            "type": "object",
            "properties": td.get("params", {}),
            "required": td.get("required", []),
        },
    }


TOOLS_OPENAI = [_tool_def_to_openai(t) for t in TOOL_DEFS]
TOOLS_ANTHROPIC = [_tool_def_to_anthropic(t) for t in TOOL_DEFS]


_TOOL_MAP = {
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


async def execute_tool(db: Session, pid: str, name: str, args: dict) -> dict:
    fn = _TOOL_MAP.get(name)
    if fn is None:
        return {"error": f"Unknown tool: {name}"}
    try:
        result = fn(db=db, pid=pid, **args)
        if asyncio.iscoroutine(result):
            result = await result
        return result
    except Exception as e:
        logger.warning("[ai_tools] tool %s error: %s", name, e)
        return {"error": str(e)}
