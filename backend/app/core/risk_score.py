"""
Reactive host risk / priority scoring.

The score is computed on-the-fly from live data — it is NOT stored in a
column and does not require periodic background recalculation.  Every
request that needs the score calls ``compute_host_risk`` which queries the
current state of findings, credentials, and attack paths for the host.

Score breakdown (0–100):
  status_rank      0–30  (how far compromised)
  findings         0–25  (severity-weighted finding counts)
  role_criticality 0–15  (DC, database, server, etc.)
  cred_reuse       0–15  (credentials valid on 2+ hosts)
  attack_paths     0–15  (paths that pass through this host)
"""

from __future__ import annotations

from typing import Any

from .. import models

_STATUS_SCORE = {
    "unknown": 0,
    "alive": 3,
    "up": 5,
    "scanned": 8,
    "access": 18,
    "compromised": 25,
    "pwned": 28,
    "owned": 30,
    "attacker": 0,
    "down": 0,
    "unreachable": 0,
}

_ROLE_SCORE = {
    "dc": 15,
    "domain_controller": 15,
    "database": 12,
    "server": 8,
    "file_server": 8,
    "web_server": 7,
    "web": 7,
    "mail": 5,
    "jump_host": 10,
    "router": 6,
    "firewall": 6,
    "network_device": 6,
    "workstation": 2,
    "printer": 1,
    "iot": 1,
    "external": 0,
    "attacker": 0,
    "unknown": 0,
    "other": 0,
    "pivot": 5,
}

_FINDING_WEIGHTS = {
    "critical": 8,
    "high": 5,
    "medium": 3,
    "low": 1,
    "info": 0,
}


def compute_host_risk(db, host: models.Host) -> dict[str, Any]:
    """Compute a reactive risk score (0–100) for *host*.

    Returns ``{score, level, breakdown}``.
    """
    pid = host.pid

    # ── Status rank ──────────────────────────────────────────────
    status_score = _STATUS_SCORE.get((host.status or "").lower(), 0)

    # ── Findings ─────────────────────────────────────────────────
    findings = (
        db.query(models.Finding.severity, models.Finding.status)
        .filter(
            models.Finding.pid == pid,
            models.Finding.host_id == host.id,
            models.Finding.deleted_at.is_(None),
        )
        .all()
    )
    findings_score = 0
    open_count = 0
    for sev, status in findings:
        if (status or "open") in ("resolved", "fixed", "false_positive", "accepted"):
            continue
        open_count += 1
        findings_score += _FINDING_WEIGHTS.get((sev or "").lower(), 0)
    findings_score = min(findings_score, 25)

    # ── Role criticality ─────────────────────────────────────────
    role_score = _ROLE_SCORE.get((host.role or "").lower(), 0)

    # ── Credential reuse ─────────────────────────────────────────
    cred_ids = (
        db.query(models.CredHostNote.cred_id)
        .filter(models.CredHostNote.host_id == host.id)
        .distinct()
        .all()
    )
    cred_id_list = [c[0] for c in cred_ids]
    # Also check host_ids on Cred directly. Filtered in Python rather than
    # via the SQL-level ARRAY.any() comparator — that comparator is
    # Postgres-ARRAY-specific and isn't available against the JSON
    # fallback type _types.py uses for host_ids under the sqlite test
    # backend, and the candidate set is already bounded by pid.
    creds_with_host_link = [
        c
        for c in db.query(models.Cred.id, models.Cred.host_ids).filter(models.Cred.pid == pid).all()
        if host.id in (c[1] or [])
    ]
    all_cred_ids = set(cred_id_list) | {c[0] for c in creds_with_host_link}

    cred_reuse_score = 0
    reused_creds = 0
    if all_cred_ids:
        for cid in all_cred_ids:
            host_count = (
                db.query(models.CredHostNote).filter(models.CredHostNote.cred_id == cid).count()
            )
            cred_row = db.query(models.Cred).filter(models.Cred.id == cid).first()
            if cred_row and cred_row.host_ids:
                host_count = max(host_count, len(cred_row.host_ids))
            if host_count >= 2:
                reused_creds += 1
        cred_reuse_score = min(reused_creds * 5, 15)

    # ── Attack paths ─────────────────────────────────────────────
    path_count = (
        db.query(models.AttackPathNode)
        .filter(
            models.AttackPathNode.host_id == host.id,
        )
        .count()
    )
    attack_path_score = min(path_count * 3, 15)

    total = min(
        status_score + findings_score + role_score + cred_reuse_score + attack_path_score, 100
    )

    if total >= 70:
        level = "critical"
    elif total >= 50:
        level = "high"
    elif total >= 30:
        level = "medium"
    elif total >= 10:
        level = "low"
    else:
        level = "info"

    return {
        "score": total,
        "level": level,
        "breakdown": {
            "status": status_score,
            "findings": findings_score,
            "open_findings": open_count,
            "role": role_score,
            "cred_reuse": cred_reuse_score,
            "reused_creds": reused_creds,
            "attack_paths": attack_path_score,
            "path_count": path_count,
        },
    }


def compute_project_risk_scores(db, pid: str) -> dict[str, dict]:
    """Compute risk scores for all hosts in a project.

    Returns a mapping ``{host_id: {score, level, breakdown}}``.
    """
    hosts = (
        db.query(models.Host).filter(models.Host.pid == pid, models.Host.deleted_at.is_(None)).all()
    )
    return {h.id: compute_host_risk(db, h) for h in hosts}
