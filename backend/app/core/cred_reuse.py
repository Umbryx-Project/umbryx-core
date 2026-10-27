"""
Credential reuse analysis — detect password sharing patterns across hosts/users.

Groups credentials by decrypted secret value and flags clusters where the same
password is used across multiple hosts or multiple users. This is the primary
indicator for lateral movement risk.

Severity tiers:
  critical  — domain admin secret reused, or same secret on 5+ hosts
  high      — local admin or privileged secret reused on 3+ hosts
  medium    — same secret on 2+ hosts
  low       — same secret across different usernames (possible shared credential)
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from sqlalchemy.orm import Session

from .. import models
from .key_management import decrypt_for_project


def analyse_cred_reuse(db: Session, pid: str) -> dict[str, Any]:
    """Analyse credential reuse for a project.

    Returns:
        {groups: [...], stats: {total_creds, reused_creds, affected_hosts, clusters}}
    """
    creds = db.query(models.Cred).filter(models.Cred.pid == pid).all()
    notes = db.query(models.CredHostNote).filter(models.CredHostNote.pid == pid).all()
    hosts = {h.id: h for h in db.query(models.Host).filter(models.Host.pid == pid).all()}

    # Build cred → validated host list (from CredHostNote)
    cred_hosts: dict[str, list[str]] = defaultdict(list)
    cred_access: dict[str, list[str]] = {}
    for n in notes:
        cred_hosts[n.cred_id].append(n.host_id)
        if n.access:
            cred_access.setdefault(n.cred_id, []).extend(n.access)

    # Also include declared host_ids
    for c in creds:
        for hid in c.host_ids or []:
            if hid not in cred_hosts[c.id]:
                cred_hosts[c.id].append(hid)

    # Group by decrypted secret
    secret_groups: dict[str, list[models.Cred]] = defaultdict(list)
    for c in creds:
        if not c.secret:
            continue
        try:
            plain = decrypt_for_project(db, pid, c.secret)
        except Exception:
            continue
        if plain:
            secret_groups[plain].append(c)

    groups = []
    reused_cred_ids: set[str] = set()
    affected_host_ids: set[str] = set()

    for secret, group_creds in secret_groups.items():
        if len(group_creds) < 2:
            continue

        # Collect all hosts touched by this secret
        all_hosts: set[str] = set()
        usernames = set()
        is_domain = False
        has_admin = False
        services = set()
        cred_ids = []
        for c in group_creds:
            cred_ids.append(c.id)
            usernames.add(c.username)
            if c.is_domain:
                is_domain = True
            services.add(c.service) if c.service else None
            access_roles = cred_access.get(c.id, [])
            if any("admin" in r.lower() for r in access_roles):
                has_admin = True
            for hid in cred_hosts.get(c.id, []):
                all_hosts.add(hid)

        if len(all_hosts) < 2 and len(usernames) < 2:
            continue

        for cid in cred_ids:
            reused_cred_ids.add(cid)
        for hid in all_hosts:
            affected_host_ids.add(hid)

        host_count = len(all_hosts)
        user_count = len(usernames)

        # Determine severity
        if is_domain and has_admin:
            severity = "critical"
        elif host_count >= 5:
            severity = "critical"
        elif has_admin and host_count >= 3:
            severity = "high"
        elif host_count >= 3:
            severity = "high"
        elif host_count >= 2:
            severity = "medium"
        else:
            severity = "low"

        # Build host info
        host_infos = []
        for hid in sorted(all_hosts):
            h = hosts.get(hid)
            if h:
                host_infos.append(
                    {
                        "id": h.id,
                        "ip": h.ip,
                        "hostname": h.hostname,
                        "os": h.os,
                    }
                )

        groups.append(
            {
                "severity": severity,
                "usernames": sorted(usernames),
                "user_count": user_count,
                "host_count": host_count,
                "hosts": host_infos,
                "is_domain": is_domain,
                "has_admin_access": has_admin,
                "services": sorted(services),
                "cred_ids": cred_ids,
                "secret_preview": secret[:2] + "***" if len(secret) > 2 else "***",
            }
        )

    # Sort: critical first, then by host_count desc
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    groups.sort(key=lambda g: (severity_order.get(g["severity"], 9), -g["host_count"]))

    return {
        "groups": groups,
        "stats": {
            "total_creds": len(creds),
            "reused_creds": len(reused_cred_ids),
            "affected_hosts": len(affected_host_ids),
            "clusters": len(groups),
        },
    }
