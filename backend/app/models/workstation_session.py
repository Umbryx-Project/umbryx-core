"""Workstation terminal sessions (PTY tracking).

A session is one login shell on a workstation: correlated from shell-hook
events and the PTY recording (same tty). Nested SSH jumps are recorded
as a path — with explicit uncertainty: a jump detected from a command
line is a *suspected* transition until PTY output confirms it (prompt
change) or the operator's next commands carry the new host's context.
"""

from sqlalchemy import Column, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB

from ..database import Base


class WorkstationSession(Base):
    __tablename__ = "workstation_sessions"

    id = Column(String, primary_key=True)
    workstation_id = Column(
        String, ForeignKey("operator_workstations.id", ondelete="CASCADE"), nullable=False
    )
    pid = Column(String, nullable=True, index=True)
    # tty is the correlation key between hook events and the PTY recording
    tty = Column(String, nullable=False, default="")
    username = Column(String, nullable=False, default="")
    user_id = Column(String, nullable=True)
    ssh_client = Column(String, nullable=False, default="")
    # active | idle | closed — idle after SESSION_IDLE_MINUTES without events
    state = Column(String, nullable=False, default="active")
    started_at = Column(String, nullable=False)
    last_event_at = Column(String, nullable=False)
    ended_at = Column(String, nullable=True)
    # SSH chain: [{"hop": 1, "host": "10.0.0.5", "confirmed": false,
    #              "observed_at": "...", "evidence": "command|prompt"}]
    path = Column(JSONB, nullable=False, default=list)
    # PTY recording bookkeeping (harvest offsets live in workstation meta;
    # this is what the UI needs to replay the session)
    pty_log = Column(Text, nullable=False, default="")
    pty_bytes = Column(String, nullable=False, default="0")
    # telemetry freshness signal for the UI ("is this stale?")
    last_source = Column(String, nullable=False, default="")
    note = Column(Text, nullable=False, default="")

    __table_args__ = (
        Index("ix_ws_sessions_ws_tty", "workstation_id", "tty"),
        Index("ix_ws_sessions_pid_state", "pid", "state"),
    )
