"""Session lifecycle: correlate hook/PTY events into terminal sessions.

A session is (workstation, tty) — the one key both sources share. Hook
events arrive with $TTY; PTY segments are harvested per recording file,
which itself records the tty it was started under (the wrapper writes a
header line). Correlation therefore never guesses across machines.

Nested SSH: when a command's first token is an ssh-like client, we
append a hop to the session path as *unconfirmed* — a command line says
the operator *started* a jump, not where they landed or that it
succeeded. Confirmation comes later from PTY output (a prompt change
observed after the jump command) and is recorded as a separate update.
Uncertainty is explicit in the data, not silently resolved.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from ...models.workstation_session import WorkstationSession
from ..utils import new_id, ts_now

logger = logging.getLogger(__name__)

SESSION_IDLE_MINUTES = 30

# ssh-like first tokens: a jump starts when the command leads with one
# of these. sudo -u user ssh is still a jump; `git ssh://` is not.
_SSH_CMD_RE = re.compile(
    r"^(?:sudo\s+(?:-\S+\s+)*|nohup\s+|timeout\s+\d+\s+|env\s+\S+=\S+\s+)*"
    r"(?:ssh|slogin|mosh)\s+(?:-\S+\s+)*(\S+)",
)

_TARGET_RE = re.compile(
    r"(?:(?:[a-z0-9-]+)@)?((?:\d{1,3}\.){3}\d{1,3}|[a-z0-9][a-z0-9.-]*\.[a-z]{2,})", re.I
)


def _fmt_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_ts(ts: str) -> datetime | None:
    try:
        return datetime.strptime((ts or "")[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        return None


def get_or_create_session(
    db: Session, ws, tty: str, username: str = "", ssh_client: str = "", ts: str | None = None
) -> WorkstationSession:
    """Find the open session for (workstation, tty) or open one.

    A fresh login gets a fresh session: if the newest session for the
    tty is closed (or idle past the cutoff — a dead shell we never saw
    the exit for), start a new row instead of resurrecting it.
    """
    ts = ts or ts_now()
    sess = (
        db.query(WorkstationSession)
        .filter(
            WorkstationSession.workstation_id == ws.id,
            WorkstationSession.tty == (tty or ""),
            WorkstationSession.state != "closed",
        )
        .order_by(WorkstationSession.started_at.desc())
        .first()
    )
    if sess:
        last = _parse_ts(sess.last_event_at)
        cutoff = datetime.now(UTC) - timedelta(minutes=SESSION_IDLE_MINUTES)
        if not (last and last < cutoff):
            return sess

    sess = WorkstationSession(
        id=new_id("wsess"),
        workstation_id=ws.id,
        pid=ws.project_id,
        tty=(tty or "")[:60],
        username=(username or "")[:120],
        ssh_client=(ssh_client or "")[:120],
        state="active",
        started_at=ts,
        last_event_at=ts,
        path=[],
    )
    db.add(sess)
    db.flush()
    return sess


def correlate_action(db: Session, ws, action) -> WorkstationSession:
    """Attach an ingested hook/PTY action to its session (by tty).

    Also opportunistically closes the previous session when a *new*
    login lands on the same tty: the OS reuses ptys, and two shells on
    one pts is not a thing — the older row is the dead one.
    """
    ts = action.ts or ts_now()
    if action.tty:
        same_tty = (
            db.query(WorkstationSession)
            .filter(
                WorkstationSession.workstation_id == ws.id,
                WorkstationSession.tty == action.tty,
            )
            .order_by(WorkstationSession.started_at.desc())
            .all()
        )
        for older in same_tty[1:]:
            if older.state != "closed" and older.id != (action.session_id or ""):
                older.state = "closed"
                older.ended_at = ts

    sess = get_or_create_session(db, ws, action.tty, action.username, action.ssh_client, ts)
    # tty reuse: any other still-open session on this tty is the dead one
    for other in (
        db.query(WorkstationSession)
        .filter(
            WorkstationSession.workstation_id == ws.id,
            WorkstationSession.tty == (action.tty or ""),
            WorkstationSession.state != "closed",
            WorkstationSession.id != sess.id,
        )
        .all()
    ):
        other.state = "closed"
        other.ended_at = ts
    action.session_id = sess.id
    sess.last_event_at = ts
    sess.last_source = action.source or "shell-hook"
    if action.username and not sess.username:
        sess.username = action.username
    if action.ssh_client and not sess.ssh_client:
        sess.ssh_client = action.ssh_client
    db.flush()
    return sess


def _extract_jump_target(command: str) -> str:
    m = _SSH_CMD_RE.match(command.strip())
    if not m:
        return ""
    dest = m.group(1)
    # strip user@ for the host part but keep it as context if present
    at = dest.rfind("@")
    host = dest[at + 1 :] if at >= 0 else dest
    if host.startswith("-"):
        return ""
    # a bare bracketed ipv6 or a name — keep as-is
    return host.strip("[](),")


def record_ssh_jump(db: Session, sess: WorkstationSession, command: str, ts: str) -> dict | None:
    """Append an unconfirmed hop when the command starts a nested SSH.

    Returns the hop dict (also appended to sess.path) or None. The hop
    is marked confirmed=False — a command line proves intent, not a
    landed session; PTY evidence upgrades it later.
    """
    host = _extract_jump_target(command)
    if not host:
        return None
    try:
        if "/" in host or " " in host:
            return None
        ipaddress.ip_address(host.replace("[", "").replace("]", ""))
        is_ip = True
    except ValueError:
        is_ip = bool(_TARGET_RE.match(host))
        if not is_ip:
            return None

    # copy-on-write: appending to sess.path in place mutates the loaded
    # JSONB without marking the attribute dirty — the write silently
    # disappears on flush (found live on the EE stand: hops never
    # persisted). Assigning a NEW list is what makes SQLAlchemy see it.
    path = list(sess.path) if isinstance(sess.path, list) else []
    hop = {
        "hop": len(path) + 1,
        "host": host[:120],
        "confirmed": False,
        "observed_at": ts,
        "evidence": "command",
    }
    sess.path = [*path, hop]
    db.flush()
    return hop


def confirm_jump(db: Session, sess: WorkstationSession, host: str, ts: str, evidence: str = "prompt") -> None:
    """Mark a hop confirmed once PTY output supports it (prompt change,
    successful-auth line). Idempotent."""
    path = [dict(h) for h in (sess.path if isinstance(sess.path, list) else [])]
    changed = False
    for hop in path:
        if hop.get("host") == host and not hop.get("confirmed"):
            hop["confirmed"] = True
            hop["confirmed_at"] = ts
            hop["evidence"] = evidence
            changed = True
    if changed:
        # new list — see record_ssh_jump for why assignment must not be
        # the same object SQLAlchemy already holds
        sess.path = path
        db.flush()


def close_idle_sessions(db: Session, now: datetime | None = None) -> int:
    """Idle-out sessions with no events inside the window. Called lazily
    on read (same pattern as deconfliction's expired claims)."""
    now = now or datetime.now(UTC).replace(tzinfo=None)
    cutoff = _fmt_ts(now - timedelta(minutes=SESSION_IDLE_MINUTES))
    rows = (
        db.query(WorkstationSession)
        .filter(WorkstationSession.state == "active", WorkstationSession.last_event_at < cutoff)
        .all()
    )
    for row in rows:
        row.state = "closed"
        row.ended_at = row.last_event_at
    if rows:
        db.commit()
    return len(rows)
