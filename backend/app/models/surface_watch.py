"""Continuous attack-surface monitoring (SurfaceWatch model)."""

from sqlalchemy import Boolean, Column, ForeignKey, Index, Integer, String

from ..database import Base
from ._types import JSONB

_FK_PROJECTS_ID = "projects.id"


class SurfaceWatch(Base):
    """A periodic light-recon watch over a project's scope.

    Each due run captures the current host/port state, runs a quick nmap
    over the configured targets through the project's attacker transport,
    upserts results into the Host graph (the standard scan pipeline), and
    diffs the post-state against the stored baseline. Growth of the
    surface — new hosts, new open ports, status flips — notifies project
    members and lands on the timeline.
    """

    __tablename__ = "surface_watches"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey(_FK_PROJECTS_ID, ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String, nullable=False, default="Surface watch")
    enabled = Column(Boolean, nullable=False, default=True)
    interval_minutes = Column(Integer, nullable=False, default=60)
    targets = Column(String, nullable=False, default="")  # empty = project scope CIDRs
    intensity_profile = Column(String, nullable=False, default="normal")
    state = Column(String, nullable=False, default="idle")  # idle|running
    last_run_at = Column(String, nullable=True)
    last_change_at = Column(String, nullable=True)
    last_job_id = Column(String, nullable=False, default="")
    baseline_json = Column(JSONB, nullable=False, default=dict)
    last_diff_json = Column(JSONB, nullable=False, default=dict)
    created_by = Column(String, nullable=True)
    created_at = Column(String, nullable=False)

    __table_args__ = (Index("ix_surface_watches_pid_enabled", "pid", "enabled"),)
