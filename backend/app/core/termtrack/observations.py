"""Observations: create from parsed output, dedup, and apply to the project.

Flow (P2 of the termtrack spec):

    segment output -> parse_output() -> observations (dedup by hash)
                                          |
                    direct + unambiguous -+-> applied (entities updated)
                    interpretive ----------> pending (drafts for review)

Provenance is first-class: every observation keeps the command, session
and workstation it came from, so any enriched entity can link back to
the exact terminal event that produced it.
"""

from __future__ import annotations

import hashlib
import json
import logging

from sqlalchemy.orm import Session

from ...models.observation import Observation
from ..output_parser import parse_output
from ..secret_scrub import scrub_secret
from ..utils import new_id, ts_now

logger = logging.getLogger(__name__)

# Which parsed kinds are safe to auto-apply. Everything else lands as
# pending — an interpretation, not a fact (spec §4.4).
_AUTO_KINDS = {
    "host",          # a host record (direct: the tool reported it)
    "service",       # port/proto on a host
    "dns",           # resolution answer
    "network",       # interface/route context
}


def _canonical(data: dict) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def _hash(pid: str, kind: str, data: dict) -> str:
    return hashlib.sha256(f"{pid}|{kind}|{_canonical(data)}".encode()).hexdigest()


def _summary_for(kind: str, data: dict) -> str:
    if kind == "host":
        bits = [data.get("ip") or "?"]
        if data.get("hostname"):
            bits.append(f"hostname={data['hostname']}")
        if data.get("ports"):
            bits.append(f"{len(data['ports'])} port(s)")
        return "host " + " ".join(bits)
    if kind == "dns":
        return f"DNS {data.get('name')} -> {data.get('value')}"
    if kind == "network":
        if data.get("kind") == "route":
            return f"route {data.get('cidr')}" + (f" via {data['via']}" if data.get("via") else "")
        return f"iface {data.get('iface')} {data.get('cidr')}"
    if kind == "access_context":
        return f"access {data.get('username', '')}@{data.get('host', '')} priv={data.get('privileges', '')}"
    return kind


def create_observations(
    db: Session,
    pid: str,
    ws_id: str,
    command: str,
    output: str,
    session_id: str | None = None,
    action_id: str | None = None,
    observed_at: str | None = None,
) -> list[Observation]:
    """Parse a command's output and upsert observations (idempotent).

    Existing (dedup_hash, status in applied/pending) rows are returned
    untouched — re-running the same command with the same output creates
    nothing and changes nothing.
    """
    parsed = parse_output(command, output)
    ts = observed_at or ts_now()
    made: list[Observation] = []

    def _add(kind: str, data: dict, confidence: str = "direct") -> None:
        data = {k: v for k, v in data.items() if v not in (None, "", [])}
        if not data:
            return
        # secrets must never ride into observation payloads
        data = json.loads(scrub_secret(_canonical(data), ""))
        h = _hash(pid, kind, data)
        existing = db.query(Observation).filter(Observation.dedup_hash == h).first()
        if existing:
            made.append(existing)
            return
        obs = Observation(
            id=new_id("obs"),
            pid=pid,
            workstation_id=ws_id,
            session_id=session_id,
            action_id=action_id,
            tool=parsed.get("tool") or "",
            kind=kind,
            data=data,
            confidence=confidence,
            status="pending",
            dedup_hash=h,
            observed_at=ts,
            provenance={
                "command": command[:1000],
                "session_id": session_id,
                "action_id": action_id,
                "workstation_id": ws_id,
            },
            summary=_summary_for(kind, data),
        )
        db.add(obs)
        made.append(obs)

    # impacket-style connection strings carry the identity and the target
    # in the COMMAND itself — richer than what the output shows
    from ..output_parser import parse_impacket_connection

    if parsed.get("tool") in ("psexec_family", "secretsdump", "getuserspns",
                              "getnpusers", "ntlmrelayx"):
        conn = parse_impacket_connection(command)
        for h in conn.get("hosts", []):
            if h.get("ip") or h.get("hostname"):
                _add("host", h)
        for c in conn.get("creds", []):
            _add("access_context",
                 {"username": c.get("username"), "domain": c.get("domain"),
                  "host": c.get("host"), "privileges": "",
                  "auth": "secret" if c.get("has_secret") else ""},
                 confidence="inferred")

    for h in parsed.get("hosts", []):
        if h.get("_local"):
            # ss output about the operator's own box is context, not a target
            continue
        _add("host", {"ip": h.get("ip"), "hostname": h.get("hostname"), "os": h.get("os"),
                      "domain": h.get("domain"), "ports": h.get("ports"), "services": h.get("services")})
    for n in parsed.get("network", []):
        _add("network", n)
    for d in parsed.get("dns", []):
        _add("dns", d)
    # creds never auto-apply: they are the textbook "needs interpretation"
    for c in parsed.get("creds", []):
        _add("access_context", {"username": c.get("username"), "domain": c.get("domain"),
                                "host": c.get("host"), "privileges": ""}, confidence="inferred")

    db.flush()
    return made
