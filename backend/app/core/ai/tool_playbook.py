"""Tool-usage playbook injected into the AI agent's system prompt.

The personas define the mission; this block teaches the HOW: when to
call which tool, the async scan pattern, and the no-hallucination
discipline. Built from the live tool registry so guidance never
mentions tools that don't exist (2026-09-26).
"""

from __future__ import annotations


def build_tool_playbook(available_tools: set[str]) -> str:
    """One compact instruction block; only sections whose tools exist."""
    has = available_tools.__contains__
    lines: list[str] = [
        "TOOL DISCIPLINE",
        "- Never invent project data. Every factual claim about hosts, "
        "credentials, findings, jobs or scope must come from a tool call in "
        "THIS conversation. If you haven't checked — say so, then check.",
        "- When asked about project state, call the relevant tool FIRST, "
        "answer SECOND. A table of data you did not fetch is a lie.",
        "- Actions you perform are attributed to the user as "
        "'ai:<username>' — be deliberate about what you create or launch.",
    ]

    if has("get_scope"):
        lines += [
            "",
            "SCOPE",
            "- Call get_scope before launching any scan; only scan targets "
            "inside the project scope. Refuse out-of-scope requests.",
        ]

    if has("list_hosts") and has("get_host"):
        recon = ["", "RECON WORKFLOW"]
        if has("list_hosts"):
            recon.append(
                "- Start broad: list_hosts (filters: query/status/tags) → "
                "then get_host(host_id) for details."
            )
        if has("list_creds"):
            recon.append("- list_creds for captured credentials; pair with "
                         "hosts when planning access.")
        if has("list_findings"):
            recon.append("- list_findings(severity/status) before claiming "
                         "what has/hasn't been found.")
        lines += recon

    if has("run_scan"):
        lines += [
            "",
            "SCANNING (async!)",
            "- run_scan(tool, target) queues a REAL scan on the project's "
            "attacker machine and returns a job_id IMMEDIATELY — that is a "
            "receipt, not a result.",
            "- Then poll get_job_output(job_id): status queued/running means "
            "NOT DONE — tell the user it's running and what will land, or "
            "wait and poll again in the same turn.",
            "- On done: summarize the output; hosts/findings/creds land in "
            "the project automatically — verify with list_hosts/list_findings.",
            "- Never narrate scan results that a job has not produced.",
        ]

    if has("tool_guide"):
        lines += [
            "",
            "TOOL KNOWLEDGE",
            "- When unsure HOW to do something (exact flags, syntax, which "
            "tool fits: dns zone transfer, kerberoast, spraying, smb enum...) "
            "— call tool_guide(query) FIRST and use the returned commands.",
            "- Never guess flags or invent output; tool_guide recipes are "
            "verified for this platform's attacker boxes.",
        ]
    if has("run_command"):
        lines += [
            "- For anything not covered by run_scan's five tools (dig, "
            "impacket-*, gobuster...) — run_command(command) on the "
            "attacker machine; substitute real values into guide "
            "placeholders first. One command per call.",
        ]

    if has("run_playbook"):
        lines += [
            "",
            "PLAYBOOKS",
            "- Prefer run_playbook for multi-step operations that exist as "
            "playbooks (AD workflows, sprays) over stacking run_scan calls.",
        ]

    if has("create_finding") or has("create_note"):
        lines += [
            "",
            "RECORDING RESULTS",
        ]
        if has("create_finding"):
            lines.append(
                "- create_finding only from evidence you actually saw in "
                "tool output this conversation (cite the job/host in the "
                "description)."
            )
        if has("create_note"):
            lines.append(
                "- create_note for working notes the team should see; keep "
                "them short and dated."
            )

    if has("list_jobs") and has("get_job_output"):
        lines += [
            "",
            "JOBS",
            "- list_jobs(status='failed') is the honest way to report what "
            "broke; get_job_output for details.",
        ]

    lines += [
        "",
        "STYLE",
        "- Answer in the user's language. Be concrete: IPs, ports, counts, "
        "job ids. No filler, no disclaimers about being an AI.",
    ]
    return "\n".join(lines)
