"""Structured observations extracted from workstation terminal output.

An observation is one extracted fact with full provenance: which command
produced it, in which session, on which workstation, seen when — and a
dedup hash so re-processing the same output (harvest re-runs, repeated
commands) never creates a second copy.

Status lifecycle:
    pending  — extracted, needs human interpretation (draft)
    applied  — merged into project entities (auto or approved)
    dismissed — reviewed and rejected by an operator

Confidence:
    direct   — literal, unambiguous output (an open port line, a DNS answer)
    inferred — parser heuristics (hostname from a prompt, OS from a banner)
"""

from sqlalchemy import Column, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB

from ..database import Base


class Observation(Base):
    __tablename__ = "observations"

    id = Column(String, primary_key=True)
    pid = Column(String, nullable=False, index=True)
    workstation_id = Column(String, ForeignKey("operator_workstations.id", ondelete="CASCADE"), nullable=False)
    session_id = Column(String, ForeignKey("workstation_sessions.id", ondelete="SET NULL"), nullable=True)
    action_id = Column(String, ForeignKey("workstation_actions.id", ondelete="SET NULL"), nullable=True)
    tool = Column(String, nullable=False, default="")
    # host | service | network | dns | domain | scan | access_context
    kind = Column(String, nullable=False)
    # kind-specific payload: {"ip": ..., "port": ..., "proto": ...}
    data = Column(JSONB, nullable=False, default=dict)
    confidence = Column(String, nullable=False, default="direct")
    status = Column(String, nullable=False, default="pending")
    # sha256(pid|kind|canonical(data)) — unique: idempotent re-processing
    dedup_hash = Column(String, nullable=False)
    observed_at = Column(String, nullable=False)
    applied_at = Column(String, nullable=True)
    # canonical JSON of what was applied and to which entities — the
    # "go to source" link plus the audit of the merge itself
    provenance = Column(JSONB, nullable=False, default=dict)
    target_host_id = Column(String, ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True)
    summary = Column(Text, nullable=False, default="")

    __table_args__ = (
        Index("uq_observations_dedup", "dedup_hash", unique=True),
        Index("ix_observations_pid_status", "pid", "status"),
    )
