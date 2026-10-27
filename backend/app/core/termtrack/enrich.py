"""Apply observations to project entities.

Reuses the merge policy the platform already applies to job outputs
(bulk_actions): never overwrite a non-empty field with a parsed guess —
fill gaps, merge lists, keep the earliest observation as the record of
when something was first seen.

Two-phase per spec §4.4:
- direct observations (open port, DNS answer, literal host) auto-apply;
- inferred ones (access context, parsed "maybe a hostname") stay
  pending until an operator approves.

Conflicts: when new data disagrees with stored data, the observation is
kept pending with the discrepancy recorded in provenance.conflict —
never silently overwriting (spec §4.3).
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from ... import models
from ...models.observation import Observation
from ..utils import ts_now

logger = logging.getLogger(__name__)


def _merge_list(existing: list | None, incoming: list | None) -> list | None:
    if not incoming:
        return None
    cur = list(existing or [])
    changed = False
    for item in incoming:
        if item not in cur:
            cur.append(item)
            changed = True
    return cur if changed else None


def apply_observation(db: Session, obs: Observation, auto: bool = False) -> dict:
    """Apply one observation. `auto=True` only applies direct-confidence
    kinds (the automatic path); manual approval passes auto=False and
    applies regardless of confidence. Returns the apply report."""
    if obs.status == "applied":
        return {"changed": False, "reason": "already applied"}
    if obs.confidence != "direct" and auto:
        return {"changed": False, "reason": "inferred stays pending"}

    report: dict = {"changed": False, "entities": []}
    ts = ts_now()

    if obs.kind == "host":
        report = _apply_host(db, obs)
    elif obs.kind == "dns":
        report = _apply_dns(db, obs)
    elif obs.kind == "network":
        # network facts enrich the project's scope candidates, not hosts;
        # for now they are recorded only (surfaced via the API + UI hint)
        report = {"changed": True, "entities": [], "note": "network context recorded"}
    elif obs.kind == "access_context":
        report = _apply_access_context(db, obs)
    else:
        report = {"changed": False, "reason": f"unknown kind {obs.kind}"}

    obs.status = "applied" if report.get("changed") else "dismissed" if report.get("drop") else obs.status
    if obs.status == "applied":
        obs.applied_at = ts
    prov = dict(obs.provenance or {})
    prov["apply"] = report
    obs.provenance = prov
    db.flush()
    return report


def _project(db: Session, pid: str):
    return db.query(models.Project).filter(models.Project.id == pid).first()


def _apply_host(db: Session, obs: Observation) -> dict:
    pid = obs.pid
    data = obs.data or {}
    ip = data.get("ip")
    if not ip:
        return {"changed": False, "reason": "no ip"}
    # No deleted_at filter: (pid, ip) is UNIQUE in the DB, so a soft-
    # deleted row with the same IP would make the INSERT below blow up
    # with UniqueViolation (found live: termtrack harvest died on the
    # first host observation after the operator re-deleted a host).
    # A tombstone match RESURRECTS instead — same semantics as the scan
    # upserts: old data was deleted deliberately, so ports/services
    # restart from what the observation actually saw.
    host = (
        db.query(models.Host)
        .filter(models.Host.pid == pid, models.Host.ip == ip)
        .first()
    )
    if host and host.deleted_at:
        host.deleted_at = None
        host.status = "alive"
        host.ports = []
        host.services = []
    created = False
    if not host:
        host = models.Host(
            id=new_host_id(db), pid=pid, ip=ip,
            hostname="", os="", status="alive", ports=[], services=[],
            ips=[], tags=[], domain="", role="unknown", import_source="termtrack",
        )
        db.add(host)
        db.flush()
        created = True

    conflicts: list[dict] = []
    entities: list[dict] = []

    def _fill(field: str, value):
        if not value:
            return
        current = getattr(host, field, None)
        if not current:
            setattr(host, field, value)
            entities.append({"entity": "host", "id": host.id, "field": field, "old": current, "new": value})
        elif current != value:
            conflicts.append({"field": field, "stored": current, "observed": value})

    _fill("hostname", data.get("hostname"))
    _fill("os", data.get("os"))
    _fill("domain", data.get("domain"))
    for field in ("ports", "services"):
        merged = _merge_list(getattr(host, field, None), data.get(field))
        if merged is not None:
            entities.append({"entity": "host", "id": host.id, "field": field,
                             "old": getattr(host, field), "new": merged})
            setattr(host, field, merged)

    obs.target_host_id = host.id
    if conflicts and not entities and not created:
        # pure disagreement — do not overwrite, record it (spec §4.3)
        return {"changed": False, "drop": False, "conflict": conflicts,
                "reason": "contradicts stored data; kept for review"}

    return {"changed": True, "created": created, "entities": entities,
            "conflict": conflicts or None}


def _apply_dns(db: Session, obs: Observation) -> dict:
    data = obs.data or {}
    ip, name = data.get("value"), data.get("name")
    if not ip or not name or data.get("type") not in ("A", "AAAA"):
        return {"changed": False, "reason": "not a forward record"}
    host = (
        db.query(models.Host)
        .filter(models.Host.pid == obs.pid, models.Host.ip == ip, models.Host.deleted_at.is_(None))
        .first()
    )
    if host:
        if not host.hostname:
            host.hostname = name
            obs.target_host_id = host.id
            return {"changed": True, "entities": [{"entity": "host", "id": host.id, "field": "hostname",
                                                   "old": "", "new": name}]}
        if host.hostname == name:
            return {"changed": True, "entities": [], "reason": "already known"}
        return {"changed": False, "conflict": [{"field": "hostname", "stored": host.hostname,
                                                "observed": name}],
                "reason": "contradicts stored hostname"}
    return {"changed": False, "reason": "host not in project (no auto-create from DNS alone)"}


def _apply_access_context(db: Session, obs: Observation) -> dict:
    """Access context is interpretive by nature: attach to the host when
    it exists, as a note — never create creds or claim access success."""
    data = obs.data or {}
    host_ip = data.get("host")
    host = None
    if host_ip:
        host = (
            db.query(models.Host)
            .filter(models.Host.pid == obs.pid, models.Host.ip == host_ip, models.Host.deleted_at.is_(None))
            .first()
        )
    if not host:
        return {"changed": False, "reason": "no host to attach context to"}
    obs.target_host_id = host.id
    # recorded on the observation itself; linking into cred-host notes is
    # a manual confirmation step (creds are never auto-created from
    # terminal output alone)
    return {"changed": True, "entities": [{"entity": "observation", "id": obs.id, "host_id": host.id}]}


def new_host_id(db: Session) -> str:
    from ..utils import new_id

    return new_id("hst")


def apply_pending_for_project(db: Session, pid: str, limit: int = 200) -> dict:
    """Automatic pass: apply every direct-confidence pending observation.
    Called after harvests; also safe to call manually."""
    rows = (
        db.query(Observation)
        .filter(Observation.pid == pid, Observation.status == "pending",
                Observation.confidence == "direct")
        .order_by(Observation.observed_at.asc())
        .limit(limit)
        .all()
    )
    applied = 0
    for obs in rows:
        r = apply_observation(db, obs, auto=True)
        if r.get("changed"):
            applied += 1
    if rows:
        db.commit()
    return {"considered": len(rows), "applied": applied}
