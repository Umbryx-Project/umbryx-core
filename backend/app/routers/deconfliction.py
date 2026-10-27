"""Deconfliction: per-host engagement map + soft host claims.

Two operators quietly working the same target break each other — double
noisy scans, conflicting exploits, trampled OPSEC. This module gives the
signal to prevent it:

- GET  /api/projects/{pid}/deconfliction — per-host engagement map:
  active claims plus operators with running jobs against the host
  (matched by target string containing the host IP). Expired claims are
  lazily deactivated on read.
- POST /api/projects/{pid}/hosts/{hid}/claim — take/extend a soft claim
  (idle TTL, see ENGAGEMENT_IDLE_MINUTES). 409 if another operator holds an
  active claim.
- DELETE .../claim — release (own claim, or any claim for admins). Release is
  the operator's highest-authority clear: it also dismisses engagement that
  only came from a job or workstation shell activity, so it succeeds even
  when there is no claim to drop.

Claims are advisory by design: the UI warns, nothing hard-blocks — an
engagement tool must never refuse the operator a manual override.
"""

from __future__ import annotations

from datetime import UTC
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import models
from ..core.access import check_pid_access
from ..core.deps import get_current_user
from ..core.enums import UserRole
from ..core.events import bcast
from ..core.utils import new_id, ts_now
from ..database import get_db
from ..models.host_claim import HostClaim

router = APIRouter(tags=["deconfliction"])

# Engagement is cleared two ways, in this order of authority:
#   1. the Release button — an explicit release outranks every signal below,
#      including a still-running job, until the operator touches the host
#      again (see released_at on HostClaim);
#   2. idle timeout — after this long without activity on the host, the claim
#      expires and workstation shell activity goes stale on its own.
# Jobs keep their own, longer freshness window: a queued or running job is a
# real deconfliction signal regardless of how long it has been going.
ENGAGEMENT_IDLE_MINUTES = 10
CLAIM_TTL_MINUTES = ENGAGEMENT_IDLE_MINUTES
WS_ACTIVITY_MINUTES = ENGAGEMENT_IDLE_MINUTES
JOB_FRESHNESS_MINUTES = 60


class ClaimBody(BaseModel):
    note: str = Field("", max_length=500)


def _deactivate_expired(db: Session, now: str) -> None:
    rows = db.query(HostClaim).filter(HostClaim.active.is_(True), HostClaim.expires_at < now).all()
    for row in rows:
        row.active = False
    if rows:
        db.commit()


def _engagement_map(db: Session, pid: str, now: str) -> dict:
    """host_id -> {"operators": [...], "claimed_by_me" unavailable here}"""
    from datetime import datetime, timedelta

    _deactivate_expired(db, now)
    hosts = (
        db.query(models.Host)
        .filter(models.Host.pid == pid, models.Host.deleted_at.is_(None))
        .all()
    )
    host_by_ip = {h.ip: h.id for h in hosts if h.ip}

    claims = (
        db.query(HostClaim)
        .filter(HostClaim.pid == pid, HostClaim.active.is_(True))
        .all()
    )

    # The Release button outranks every signal: for each (host, operator) take
    # the newest release and ignore anything that happened at or before it.
    # Activity after a release re-engages the host, which is what an operator
    # going back to work on it means.
    released: dict[tuple[str, str], str] = {}
    for row in (
        db.query(HostClaim)
        .filter(HostClaim.pid == pid, HostClaim.released_at.isnot(None))
        .all()
    ):
        key = (row.host_id, row.username or row.user_id)
        if row.released_at > released.get(key, ""):
            released[key] = row.released_at

    def _released_over(host_id: str, uname: str, signal_ts: str) -> bool:
        cutoff = released.get((host_id, uname))
        return bool(cutoff and signal_ts and signal_ts <= cutoff)

    now_dt = datetime.now(UTC).replace(tzinfo=None)
    fresh_cutoff = (now_dt - timedelta(minutes=JOB_FRESHNESS_MINUTES)).strftime("%Y-%m-%dT%H:%M:%SZ")
    jobs = (
        db.query(models.Job)
        .filter(
            models.Job.pid == pid,
            models.Job.status.in_(["queued", "running"]),
            models.Job.created_at >= fresh_cutoff,
        )
        .all()
    )

    # Merge key is username: claims carry user_id, jobs only created_by
    # (= username) — the same operator must land in one entry.
    operators: dict[str, dict[str, dict]] = {h.id: {} for h in hosts}
    # Workstation shell activity (audit log): an operator actively typing
    # commands against a host IP is the strongest busy-signal there is.
    from datetime import timedelta as _td

    ws_cutoff = (now_dt - _td(minutes=WS_ACTIVITY_MINUTES)).strftime("%Y-%m-%dT%H:%M:%SZ")
    from ..models.workstation_action import WorkstationAction

    ws_actions = (
        db.query(WorkstationAction)
        .filter(WorkstationAction.ts >= ws_cutoff, WorkstationAction.command != "")
        .all()
    )
    ws_by_id = {w.id: w for w in db.query(models.OperatorWorkstation).all()}
    from ..core.workstation.actions import extract_target_ips

    for a in ws_actions:
        ws = ws_by_id.get(a.workstation_id)
        if not ws or ws.project_id != pid:
            continue
        for ip in extract_target_ips(a.command):
            hid = host_by_ip.get(ip)
            if not hid:
                continue
            uname = a.username or ws.user_id or "workstation"
            if _released_over(hid, uname, a.ts):
                continue
            entry = operators.setdefault(hid, {}).setdefault(
                uname,
                {"username": uname, "user_id": "", "sources": [], "since": a.ts},
            )
            if "ws" not in entry["sources"]:
                entry["sources"].append("ws")
                entry["workstation"] = ws.name

    for c in claims:
        uname = c.username or c.user_id
        if _released_over(c.host_id, uname, c.claimed_at):
            continue
        entry = operators.setdefault(c.host_id, {}).setdefault(
            uname,
            {"username": uname, "user_id": c.user_id, "sources": [], "since": c.claimed_at},
        )
        entry["sources"].append("claim")
        if c.note:
            entry["note"] = c.note

    for j in jobs:
        if not j.target or not j.created_by:
            continue
        target_ip = j.target.strip()
        hid = host_by_ip.get(target_ip)
        if not hid:
            # targets like "10.0.0.0/24" — attribute to exact hosts inside
            matches = [h for h in hosts if h.ip and h.ip in target_ip]
            if len(matches) != 1:
                continue  # subnet jobs aren't attributed to a single host
            hid = matches[0].id
        if _released_over(hid, j.created_by, j.created_at):
            continue
        entry = operators.setdefault(hid, {}).setdefault(
            j.created_by,
            {"username": j.created_by, "user_id": "", "sources": [], "since": j.created_at},
        )
        if "job" not in entry["sources"]:
            entry["sources"].append("job")

    return {
        hid: {"operators": list(per_user.values())}
        for hid, per_user in operators.items()
        if per_user
    }


@router.get("/api/projects/{pid}/deconfliction")
def get_engagement(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "hosts.read")
    now = ts_now()
    engagement = _engagement_map(db, pid, now)
    # mark which busy hosts are someone else's (for warning styling)
    for entry in engagement.values():
        for op in entry["operators"]:
            op["is_me"] = op["username"] == user.username
    return {"engagement": engagement, "ttl_minutes": CLAIM_TTL_MINUTES}


@router.post("/api/projects/{pid}/hosts/{hid}/claim")
def claim_host(
    pid: str,
    hid: str,
    body: ClaimBody,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "hosts.create")
    host = (
        db.query(models.Host)
        .filter(models.Host.id == hid, models.Host.pid == pid, models.Host.deleted_at.is_(None))
        .first()
    )
    if not host:
        raise HTTPException(404)

    from datetime import datetime, timedelta

    now = ts_now()
    _deactivate_expired(db, now)
    now_dt = datetime.now(UTC).replace(tzinfo=None)
    expires = (now_dt + timedelta(minutes=CLAIM_TTL_MINUTES)).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Claiming is a deliberate re-engagement, so it voids this operator's
    # earlier dismissals of the host. Clearing the marker rather than relying
    # on timestamps also keeps the result correct when a release and a reclaim
    # land inside the same second (ts_now() is second-granular).
    for marker in (
        db.query(HostClaim)
        .filter(
            HostClaim.pid == pid,
            HostClaim.host_id == hid,
            HostClaim.user_id == user.id,
            HostClaim.released_at.isnot(None),
        )
        .all()
    ):
        marker.released_at = None

    active = (
        db.query(HostClaim)
        .filter(HostClaim.host_id == hid, HostClaim.active.is_(True))
        .all()
    )
    for c in active:
        if c.user_id == user.id:
            c.expires_at = expires  # re-claim extends
            c.note = body.note or c.note
            db.commit()
            bcast(pid, "host", "claim", {"host_id": hid, "user_id": user.id, "username": user.username})
            return {"status": "extended", "expires_at": expires}
        raise HTTPException(409, f"Host is engaged by {c.username or 'another operator'}")

    claim = HostClaim(
        id=new_id("clm"),
        pid=pid,
        host_id=hid,
        user_id=user.id,
        username=user.username,
        note=body.note,
        claimed_at=now,
        expires_at=expires,
    )
    db.add(claim)
    db.commit()
    bcast(pid, "host", "claim", {"host_id": hid, "user_id": user.id, "username": user.username})
    return {"status": "claimed", "expires_at": expires}


@router.delete("/api/projects/{pid}/hosts/{hid}/claim", status_code=204)
def release_host(
    pid: str,
    hid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "hosts.create")
    now = ts_now()
    claim = (
        db.query(HostClaim)
        .filter(HostClaim.host_id == hid, HostClaim.pid == pid, HostClaim.active.is_(True))
        .first()
    )
    if claim and claim.user_id != user.id and user.role != UserRole.PLATFORM_ADMIN:
        raise HTTPException(403, f"Claim held by {claim.username or 'another operator'}")

    if claim:
        claim.active = False
        claim.released_at = now
    else:
        # No claim to drop, but the host can still read as engaged by this
        # operator through a job or workstation shell activity. Release is the
        # operator's top-priority "I am done here", so record the dismissal
        # instead of refusing it — the engagement map honours released_at for
        # every signal, and later activity re-engages the host.
        db.add(
            HostClaim(
                id=new_id("clm"),
                pid=pid,
                host_id=hid,
                user_id=user.id,
                username=user.username,
                note="",
                active=False,
                claimed_at=now,
                expires_at=now,
                released_at=now,
            )
        )
    db.commit()
    bcast(pid, "host", "release", {"host_id": hid, "user_id": user.id})
    return None


# ── range / task claims (termtrack D, 2026-10-13) ─────────────────────
# Same advisory contract as host claims: reserve scope so colleagues see
# it; nothing hard-blocks. Ranges are CIDRs, tasks are free text.


class ScopeClaimBody(BaseModel):
    target: str = Field(..., min_length=1, max_length=200)
    note: str = Field("", max_length=500)
    # hours the reservation holds; default matches the host-claim TTL scale
    hours: float = Field(0.0, ge=0, le=72)


def _valid_range(target: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        return False


@router.get("/api/projects/{pid}/scope-claims")
def list_scope_claims(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "hosts.read")
    _deactivate_expired(db, ts_now())
    rows = (
        db.query(HostClaim)
        .filter(HostClaim.pid == pid, HostClaim.active.is_(True),
                HostClaim.claim_type.in_(("range", "task")))
        .all()
    )
    return [
        {
            "id": c.id, "claim_type": c.claim_type, "target": c.claim_target,
            "note": c.note, "username": c.username, "user_id": c.user_id,
            "claimed_at": c.claimed_at, "expires_at": c.expires_at,
            "is_me": c.user_id == user.id,
        }
        for c in rows
    ]


@router.post("/api/projects/{pid}/scope-claims", status_code=201)
def create_scope_claim(
    pid: str,
    body: ScopeClaimBody,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "hosts.create")
    target = body.target.strip()
    claim_type = "range" if _valid_range(target) else "task"
    from datetime import datetime, timedelta

    now = ts_now()
    hours = body.hours or (CLAIM_TTL_MINUTES / 60)
    expires = (
        datetime.now(UTC).replace(tzinfo=None) + timedelta(hours=hours)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    active = (
        db.query(HostClaim)
        .filter(HostClaim.pid == pid, HostClaim.active.is_(True),
                HostClaim.claim_type == claim_type, HostClaim.claim_target == target)
        .all()
    )
    for c in active:
        if c.user_id == user.id:
            c.expires_at = expires
            c.note = body.note or c.note
            db.commit()
            bcast(pid, "deconfliction", "scope_claim", {"target": target, "username": user.username})
            return {"status": "extended", "expires_at": expires, "claim_type": claim_type}
        raise HTTPException(409, f"{target} is reserved by {c.username or 'another operator'}")

    claim = HostClaim(
        id=new_id("clm"), pid=pid, host_id=None,
        claim_type=claim_type, claim_target=target,
        user_id=user.id, username=user.username, note=body.note,
        claimed_at=now, expires_at=expires,
    )
    db.add(claim)
    db.commit()
    bcast(pid, "deconfliction", "scope_claim", {"target": target, "username": user.username})
    from ..core.events import log_event

    log_event(db, pid, user.username, "claim", "created",
              f"{claim_type} claim: {target}" + (f" — {body.note}" if body.note else ""),
              {"claim_id": claim.id, "claim_type": claim_type})
    return {"status": "claimed", "expires_at": expires, "claim_type": claim_type, "id": claim.id}


@router.delete("/api/projects/{pid}/scope-claims/{cid}", status_code=204)
def release_scope_claim(
    pid: str,
    cid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "hosts.create")
    claim = (
        db.query(HostClaim)
        .filter(HostClaim.id == cid, HostClaim.pid == pid,
                HostClaim.claim_type.in_(("range", "task")))
        .first()
    )
    if not claim:
        raise HTTPException(404)
    if claim.user_id != user.id and user.role != UserRole.PLATFORM_ADMIN:
        raise HTTPException(403)
    claim.active = False
    claim.released_at = ts_now()
    db.commit()
    bcast(pid, "deconfliction", "scope_release", {"target": claim.claim_target})
    from ..core.events import log_event

    log_event(db, pid, user.username, "claim", "released",
              f"{claim.claim_type} claim released: {claim.claim_target}",
              {"claim_id": claim.id})
    return None


def _ranges_overlap(a: str, b: str) -> bool:
    import ipaddress

    try:
        na, nb = ipaddress.ip_network(a, strict=False), ipaddress.ip_network(b, strict=False)
        return na.overlaps(nb)
    except ValueError:
        return False


@router.get("/api/projects/{pid}/deconfliction/warnings")
def deconfliction_warnings(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    """Cross-operator overlap signals (advisory, never blocking).

    Sources: live engagement map (several operators on one host), scan
    commands against overlapping CIDRs, and range claims intersecting
    actual activity. Each warning names the operators and the overlap.
    """
    check_pid_access(db, pid, user, "hosts.read")
    now = ts_now()
    warnings: list[dict] = []

    # 1) several operators engaged on the same host
    engagement = _engagement_map(db, pid, now)
    for hid, entry in engagement.items():
        ops = entry["operators"]
        if len(ops) > 1:
            names = sorted({o["username"] for o in ops})
            warnings.append({
                "kind": "host_overlap", "host_id": hid,
                "operators": names,
                "message": f"{len(names)} operators engaged on one host: {', '.join(names)}",
            })

    # 2) scan commands vs range claims (and overlapping range claims)
    from datetime import datetime, timedelta

    cutoff = (
        datetime.now(UTC).replace(tzinfo=None) - timedelta(minutes=WS_ACTIVITY_MINUTES)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    import ipaddress as _ipa
    import re as _re

    from ..models.workstation_action import WorkstationAction

    scan_cmd_re = _re.compile(r"\b(nmap|masscan|rustscan|fscan)\b", _re.I)
    # non-capturing: findall must yield whole CIDRs, not the last group
    range_re = _re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")
    scanned: dict[str, str] = {}  # cidr -> username
    ws_by_id = {w.id: w for w in db.query(models.OperatorWorkstation).all()}
    for a in (
        db.query(WorkstationAction)
        .filter(WorkstationAction.ts >= cutoff, WorkstationAction.command != "")
        .all()
    ):
        ws = ws_by_id.get(a.workstation_id)
        if not ws or ws.project_id != pid or not scan_cmd_re.search(a.command):
            continue
        for cidr in range_re.findall(a.command):
            uname = a.username or ws.user_id or "workstation"
            prev = scanned.get(cidr)
            if prev and prev != uname:
                warnings.append({
                    "kind": "scan_overlap", "cidr": cidr,
                    "operators": sorted({prev, uname}),
                    "message": f"overlapping scans of {cidr} by {prev} and {uname}",
                })
            scanned[cidr] = uname

    active_ranges = [
        c for c in db.query(HostClaim)
        .filter(HostClaim.pid == pid, HostClaim.active.is_(True), HostClaim.claim_type == "range")
        .all()
    ]
    for c in active_ranges:
        for cidr, uname in scanned.items():
            if _ranges_overlap(c.claim_target, cidr) and (c.username or c.user_id) != uname:
                warnings.append({
                    "kind": "claim_conflict", "cidr": cidr, "claim": c.claim_target,
                    "operators": sorted({c.username or "claim", uname}),
                    "message": f"{uname} is scanning {cidr}, claimed by {c.username or 'another operator'}",
                })

    # 3) operator engaging a host inside someone else's range claim
    hosts = {h.id: h for h in db.query(models.Host).filter(
        models.Host.pid == pid, models.Host.deleted_at.is_(None)).all()}
    for c in active_ranges:
        for hid, entry in engagement.items():
            host = hosts.get(hid)
            if not host or not host.ip:
                continue
            try:
                if _ipa.ip_address(host.ip) not in _ipa.ip_network(c.claim_target, strict=False):
                    continue
            except ValueError:
                continue
            for o in entry["operators"]:
                uname = o["username"]
                if uname and (c.username or c.user_id) != uname:
                    warnings.append({
                        "kind": "claim_conflict", "host_id": hid, "claim": c.claim_target,
                        "operators": sorted({c.username or "claim", uname}),
                        "message": f"{uname} is working on {host.ip} inside range {c.claim_target} claimed by {c.username or 'another operator'}",
                    })

    return {"warnings": warnings, "generated_at": now}
