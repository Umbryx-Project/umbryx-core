"""PTY ingest pipeline: harvested bytes -> actions -> observations.

Dedup contract (spec §2): one executed command must yield ONE event.
When the shell has both the hook and the PTY recording running, the hook
row (exact command, exit attribution) wins and the PTY side only
supplies what the hook cannot see — the output. Match key: (workstation,
command, tty) inside a small time window.

Tail handling: output of a still-running command isn't complete at
harvest time. The unconsumed bytes after the last marker are kept as a
per-file tail (bounded) and re-processed next round; a *new* marker
closes the previous segment.
"""

from __future__ import annotations

import logging

from sqlalchemy.orm import Session

from ...models.workstation_action import WorkstationAction
from ..events import log_event
from ..utils import new_id, ts_now
from .enrich import apply_observation
from .observations import create_observations
from .segment import OSC_MARKER_RE, decode_marker, strip_ansi

logger = logging.getLogger(__name__)

TAIL_CAP = 32_000
DEDUP_WINDOW_SECONDS = 15


def _ts_close(a: str, b: str) -> bool:
    from datetime import datetime

    def _p(ts: str):
        try:
            return datetime.strptime((ts or "")[:19], "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            return None

    ta, tb = _p(a), _p(b)
    return bool(ta and tb and abs((ta - tb).total_seconds()) <= DEDUP_WINDOW_SECONDS)


def _find_hook_twin(db: Session, ws_id: str, command: str, tty: str, ts: str):
    """The shell-hook row for the same execution, if the hook saw it."""
    if not tty:
        return None
    twins = (
        db.query(WorkstationAction)
        .filter(
            WorkstationAction.workstation_id == ws_id,
            WorkstationAction.command == command,
            WorkstationAction.tty == tty,
            WorkstationAction.source == "shell-hook",
        )
        .order_by(WorkstationAction.ts.desc())
        .limit(5)
        .all()
    )
    for twin in twins:
        if _ts_close(twin.ts, ts):
            return twin
    return None


def ingest_pty_bytes(db: Session, ws, sess, filename: str, new_text: str, tail: str = "") -> dict:
    """Process one harvested chunk. Returns (stats, new_tail)."""
    buf = tail + new_text
    stats = {"commands": 0, "observations": 0, "applied": 0}

    marks = list(OSC_MARKER_RE.finditer(buf))
    if not marks:
        # no closed segment yet — everything stays pending
        return stats, buf[-TAIL_CAP:]

    # closed segments: every marker except the last one is closed by its
    # successor. The last marker's segment is still running — the tail
    # carries the marker ITSELF forward so the next round can close it.
    complete: list[tuple[str, str]] = []
    for i, m in enumerate(marks[:-1]):
        end = marks[i + 1].start()
        command = decode_marker(m.group(1))
        if not command:
            continue
        complete.append((command, strip_ansi(buf[m.end() : end])[:20_000]))

    new_tail = buf[marks[-1].start():][-TAIL_CAP:] if marks else buf[-TAIL_CAP:]

    pid = ws.project_id
    for command, output in complete:
        ts = ts_now()
        twin = _find_hook_twin(db, ws.id, command, sess.tty, ts)
        action = twin
        if twin is None:
            action = WorkstationAction(
                id=new_id("wsa"),
                workstation_id=ws.id,
                pid=pid,
                username=sess.username[:120],
                cwd="",
                ssh_client=sess.ssh_client[:120],
                tty=sess.tty[:60],
                source="pty",
                command=command[:4000],
                ts=ts,
            )
            db.add(action)
            db.flush()
        action.session_id = sess.id
        sess.last_event_at = ts
        sess.last_source = "pty"
        stats["commands"] += 1

        if not pid or not output.strip():
            continue

        # nested-SSH: commands inside a landed jump session carry the hop
        # host as their working context (uncertain by design)
        from .sessions import record_ssh_jump

        record_ssh_jump(db, sess, command, ts)

        made = create_observations(
            db, pid, ws.id, command, output,
            session_id=sess.id, action_id=action.id, observed_at=ts,
        )
        stats["observations"] += len(made)
        for obs in made:
            if obs.status == "pending" and obs.confidence == "direct":
                r = apply_observation(db, obs, auto=True)
                if r.get("changed"):
                    stats["applied"] += 1
                    if obs.kind == "host" and r.get("created"):
                        log_event(
                            db, pid, sess.username or "workstation",
                            "observation", "host_discovered",
                            f"Auto: host {obs.data.get('ip')}"
                            + (f" ({obs.data.get('hostname')})" if obs.data.get("hostname") else ""),
                            {"observation_id": obs.id, "session_id": sess.id,
                             "workstation": ws.name, "tool": obs.tool},
                            ts=ts,
                        )

    db.flush()
    return stats, new_tail
