"""Project access info: everything an operator needs to connect to the
project's C2 and infrastructure (Output → Access tab).

Aggregates in one project-scoped response:
- C2 integrations covering this project with DECRYPTED operator
  credentials and a per-type "how to connect" line;
- infra stack service credentials (ServiceCredential) filtered by the
  caller's project role against visible_to_roles;
- pool machines bound to the project with ssh addresses and whether the
  caller's key is installed.

Access control: project membership with credentials.read — same bar as
reading the project's creds page. Actual secret values additionally require
credentials.read_secret (the same permission creds.py gates "reveal" behind);
viewer/analyst-level roles see the endpoints and usernames but not secrets.
"""

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import models
from ..core.access import check_pid_access
from ..core.crypto import decrypt_str
from ..core.deps import get_current_user, is_admin
from ..core.permissions import PERM_CREDENTIALS_READ_SECRET, get_membership
from ..database import get_db

router = APIRouter(prefix="/api/projects", tags=["project-access"])


def _c2_how_to(itype: str, url: str, username: str) -> str:
    base = (url or "").rstrip("/")
    if itype == "adaptix":
        return f"Browser → {base}  (login: {username or '—'})"
    if itype == "mythic":
        return f"Browser → {base}  (Mythic UI)"
    if itype == "sliver":
        return f"sliver import operator config / connect to {base}"
    return f"Connect to {base}"


@router.get("/{pid}/access-info")
def project_access_info(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "credentials.read")

    # Security audit 2026-10-07 (finding 5): decrypted operator credentials
    # require the same permission as the creds-page "reveal" — roles with
    # only credentials.read (viewer, analyst, manager, team_lead) keep seeing
    # the integration list but without password/token/secret values.
    try:
        check_pid_access(db, pid, user, PERM_CREDENTIALS_READ_SECRET)
        can_read_secret = True
    except Exception:
        can_read_secret = False

    # ── C2: интеграции, покрывающие проект, с реальными кредами ──
    c2 = []
    try:
        from ..routers.c2._integrations import _load_integrations

        for i in _load_integrations(db):
            if i.get("enabled") is False:
                continue
            pids = i.get("project_ids") or []
            # Strict project scoping — even for admins: an Access tab must
            # show only THIS project's C2, not every shared integration.
            if pid not in pids:
                continue
            c2.append(
                {
                    "id": i.get("id"),
                    "name": i.get("name"),
                    "type": i.get("type"),
                    "url": i.get("url", ""),
                    "username": i.get("username", ""),
                    "password": i.get("password", "") if can_read_secret else "",
                    "token": i.get("token", "") if can_read_secret else "",
                    "endpoint": i.get("endpoint", ""),
                    "verify_ssl": i.get("verify_ssl", True),
                    "how_to": _c2_how_to(
                        i.get("type", ""), i.get("url", ""), i.get("username", "")
                    ),
                }
            )
    except Exception:
        c2 = []

    # ── Infra: сервисные креды стеков проекта по роли ──
    membership = get_membership(db, pid, user.id)
    user_role = membership.role if membership else None
    infra = []
    q = (
        db.query(models.ServiceCredential)
        .filter(models.ServiceCredential.project_id == pid)
        .order_by(models.ServiceCredential.created_at)
    )
    for c in q.all():
        roles = c.visible_to_roles or []
        if not is_admin(user) and roles and user_role not in roles:
            continue
        svc = (
            db.query(models.StackService).filter(models.StackService.id == c.service_id).first()
            if c.service_id
            else None
        )
        stack = db.query(models.InfraStack).filter(models.InfraStack.id == c.stack_id).first()
        infra.append(
            {
                "id": c.id,
                "stack": stack.name if stack else c.stack_id,
                "stack_status": stack.status if stack else "",
                "service": svc.name if svc else "",
                "role": svc.role if svc else "",
                "label": c.label,
                "purpose": c.purpose,
                "username": c.username,
                "secret": decrypt_str(c.secret or "") if can_read_secret else "",
                "url": c.url or (svc.connection_url if svc else None),
                "how_to": f"{c.label or 'service'} — {c.url or (svc.connection_url if svc else '')} ({c.username})",
            }
        )

    # ── Machines: pool-машины проекта ──
    machines = []
    for ws in (
        db.query(models.OperatorWorkstation)
        .filter(models.OperatorWorkstation.is_pool, models.OperatorWorkstation.project_id == pid)
        .order_by(models.OperatorWorkstation.created_at)
        .all()
    ):
        addr = ws.access_address or ""
        host, port = (addr.rsplit(":", 1) + ["22"])[:2] if addr else ("", "")
        ssh_user = (ws.meta or {}).get("ssh_user", "root") if isinstance(ws.meta, dict) else "root"
        my = (
            db.query(models.WorkstationAccess)
            .filter(
                models.WorkstationAccess.workstation_id == ws.id,
                models.WorkstationAccess.user_id == user.id,
                models.WorkstationAccess.revoked_at.is_(None),
            )
            .first()
        )
        machines.append(
            {
                "id": ws.id,
                "name": ws.name,
                "status": ws.status,
                "address": addr,
                "ssh_cmd": f"ssh {ssh_user}@{host} -p {port}" if host else "",
                "my_access": bool(my),
            }
        )

    # ── Dropped payloads: loot auto-published to the stack dropper ──
    # The dropper URL IS the payload download link — unauthenticated by
    # design (its whole point is that the target downloads the implant).
    # Handing those links to every credentials.read role made read-only
    # viewers/analysts able to pull live implants, while C2 passwords in
    # the same response were already masked (audit finding 5). Same
    # treatment now: links go to READ_SECRET roles (owner/admin/editor/
    # operator); everyone else sees only the count.
    dropped_q = (
        db.query(models.Loot)
        .filter(models.Loot.pid == pid, models.Loot.dropper_url.isnot(None))
        .order_by(models.Loot.ts.desc())
    )
    dropped_total = dropped_q.count()
    dropped = (
        [
            {
                "loot_id": loot.id,
                "filename": loot.filename or loot.value,
                "url": loot.dropper_url,
                "sha256": loot.sha256,
                "ts": loot.ts,
            }
            for loot in dropped_q.limit(50).all()
        ]
        if can_read_secret
        else []
    )

    return {
        "c2": c2,
        "infra": infra,
        "machines": machines,
        "dropped": dropped,
        "dropped_total": dropped_total,
        "dropped_restricted": not can_read_secret,
    }
