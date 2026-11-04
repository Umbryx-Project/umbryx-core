"""
Live report draft generator — auto-generates Markdown from engagement data.

Pulls from: hosts, risk scores, cred reuse, key activities, attack paths,
findings, scan diffs. Designed as a starting draft for the operator to
refine into the final deliverable.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy.orm import Session

from .. import models


def generate_report_draft(db: Session, pid: str) -> str:
    """Generate a Markdown report draft for a project."""
    project = db.query(models.Project).filter(models.Project.id == pid).first()
    if not project:
        return "# Error: Project not found"

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    # ── Gather data ────────────────────────────────────────────────────
    hosts = (
        db.query(models.Host)
        .filter(
            models.Host.pid == pid,
            models.Host.deleted_at.is_(None),
            ~models.Host.is_attacker,
        )
        .all()
    )

    creds = db.query(models.Cred).filter(models.Cred.pid == pid).all()
    findings = (
        db.query(models.Finding).filter(models.Finding.pid == pid).all()
        if hasattr(models, "Finding")
        else []
    )
    activities = db.query(models.HostActivity).filter(models.HostActivity.pid == pid).all()

    # ── Stats ────────────────────────────────────────────────────────────
    compromised = [h for h in hosts if h.status in ("compromised", "pwned", "owned")]
    by_os: dict[str, int] = {}
    for h in hosts:
        os_name = (h.os or "unknown").lower()
        by_os[os_name] = by_os.get(os_name, 0) + 1

    # ── Risk scores ────────────────────────────────────────────────────
    risk_data = []
    try:
        from .risk_score import compute_host_risk

        for h in hosts:
            score = compute_host_risk(db, h)
            risk_data.append((h, score))
        risk_data.sort(key=lambda x: x[1]["score"], reverse=True)
    except Exception:
        pass

    # ── Cred reuse ─────────────────────────────────────────────────────
    reuse_groups = []
    try:
        from .cred_reuse import analyse_cred_reuse

        reuse_data = analyse_cred_reuse(db, pid)
        reuse_groups = reuse_data.get("groups", [])
    except Exception:
        pass

    # ── Build Markdown ─────────────────────────────────────────────────
    lines: list[str] = []
    w = lines.append

    w(f"# Engagement Report — {project.name}")
    w(f"\n> **Draft auto-generated:** {now}  ")
    w(f"> **Project ID:** `{pid}`  ")
    if project.description:
        w(f"> **Description:** {project.description}  ")
    w(f"> **Status:** {project.status}  ")
    w("")

    # ── Executive Summary
    w("## Executive Summary")
    w("")
    w(f"This report covers {len(hosts)} host(s) across the engagement scope. ")
    w(f"Of these, **{len(compromised)} host(s)** were compromised, representing a ")
    w(f"compromise rate of **{round(len(compromised) / max(len(hosts), 1) * 100, 1)}%**.")
    w("")

    if compromised:
        w("**Compromised hosts:**")
        for h in compromised[:10]:
            w(f"- `{h.ip or h.hostname}` — {h.os or 'unknown OS'} — status: {h.status}")
        if len(compromised) > 10:
            w(f"- ... and {len(compromised) - 10} more")
    w("")

    # ── Host Inventory
    w("## Host Inventory")
    w("")
    w("| IP / Hostname | OS | Status | Tags |")
    w("| --- | --- | --- | --- |")
    for h in hosts[:30]:
        ip = h.ip or h.hostname or "—"
        os_name = h.os or "—"
        tags = ", ".join(h.tags or []) or "—"
        w(f"| {ip} | {os_name} | {h.status} | {tags} |")
    if len(hosts) > 30:
        w(f"\n*... {len(hosts) - 30} additional hosts omitted*")
    w("")

    if by_os:
        w("### OS Distribution")
        w("")
        for os_name, count in sorted(by_os.items(), key=lambda x: -x[1]):
            bar = "█" * min(count, 30)
            w(f"- **{os_name}**: {count} {bar}")
        w("")

    # ── Risk Assessment
    if risk_data:
        w("## Risk Assessment")
        w("")
        high_risk = [(h, s) for h, s in risk_data if s["score"] >= 50]
        medium_risk = [(h, s) for h, s in risk_data if 25 <= s["score"] < 50]
        w(f"- **Critical/High risk** (score ≥ 50): {len(high_risk)} host(s)")
        w(f"- **Medium risk** (25-49): {len(medium_risk)} host(s)")
        w(f"- **Low risk** (< 25): {len(risk_data) - len(high_risk) - len(medium_risk)} host(s)")
        w("")

        if high_risk:
            w("### Top High-Risk Hosts")
            w("")
            w("| Host | Score | Key Factors |")
            w("| --- | --- | --- |")
            for h, s in high_risk[:10]:
                factors = ", ".join(f["label"] for f in s.get("factors", []) if f["weight"] > 0)[
                    :60
                ]
                w(f"| {h.ip or h.hostname} | **{s['score']}** | {factors} |")
            w("")

    # ── Credential Analysis
    w("## Credential Analysis")
    w("")
    cracked = [c for c in creds if c.cracked]
    with_secret = [c for c in creds if c.secret]
    domain_creds = [c for c in creds if c.is_domain]
    w(f"- **Total credentials:** {len(creds)}")
    w(f"- **With secrets:** {len(with_secret)}")
    w(f"- **Cracked:** {len(cracked)}")
    w(f"- **Domain-scoped:** {len(domain_creds)}")
    w("")

    if reuse_groups:
        w("### Credential Reuse Detected")
        w("")
        for g in reuse_groups[:5]:
            severity = g["severity"].upper()
            users = ", ".join(g["usernames"][:3])
            if len(g["usernames"]) > 3:
                users += f" (+{len(g['usernames']) - 3})"
            w(
                f"- **[{severity}]** Secret shared across {g['host_count']} host(s), {g['user_count']} user(s): {users}"
            )
            if g["is_domain"]:
                w("  - ⚠ Domain credential — high lateral movement risk")
            if g["has_admin_access"]:
                w("  - ⚠ Admin access confirmed on at least one host")
        if len(reuse_groups) > 5:
            w(f"\n*... {len(reuse_groups) - 5} additional reuse clusters omitted*")
        w("")
    else:
        w("*No credential reuse patterns detected.*")
        w("")

    # ── Key Activities
    w("## Key Activities")
    w("")
    exploit_acts = [a for a in activities if a.activity_type in ("exploit", "privesc", "lateral")]
    w(f"- **Total activities:** {len(activities)}")
    w(f"- **Exploitation/privesc/lateral:** {len(exploit_acts)}")
    w("")

    if exploit_acts:
        w("### Exploitation Timeline")
        w("")
        for a in sorted(exploit_acts, key=lambda x: x.ts or "")[:15]:
            host = next((h for h in hosts if h.id == a.host_id), None)
            host_label = host.ip or host.hostname if host else "unknown"
            w(f"- **{a.ts}** — `{host_label}` — {a.title or a.activity_type}")
            if a.summary:
                w(f"  - {a.summary[:120]}")
        w("")

    # ── Findings
    if findings:
        w("## Findings")
        w("")
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings, key=lambda f: sev_order.get(getattr(f, "severity", "info").lower(), 9)
        )
        for f in sorted_findings[:20]:
            sev = getattr(f, "severity", "info").upper()
            title = getattr(f, "title", "Untitled")
            w(f"- **[{sev}]** {title}")
        if len(findings) > 20:
            w(f"\n*... {len(findings) - 20} additional findings omitted*")
        w("")

    # ── Recommendations
    w("## Recommendations")
    w("")
    recs = []
    if reuse_groups:
        recs.append(
            "1. **Rotate reused credentials** — multiple hosts share the same secret, creating lateral movement risk."
        )
    if compromised:
        recs.append(
            "2. **Investigate lateral paths** from compromised hosts to identify additional targets."
        )
    if cracked:
        recs.append(
            "3. **Review cracked credentials** — cracked passwords may provide access to additional systems."
        )
    if not recs:
        recs.append(
            "1. Continue reconnaissance and credential collection to expand engagement scope."
        )
    for r in recs:
        w(r)
    w("")

    # ── Footer
    w("---")
    w(f"*This draft was auto-generated by Umbryx on {now}. Review and refine before delivery.*")

    return "\n".join(lines)
