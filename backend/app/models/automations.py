from __future__ import annotations

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB

from ..database import Base


class PlaybookAutomation(Base):
    __tablename__ = "pb_automations"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, default="")
    enabled = Column(Boolean, default=False, nullable=False)
    definition = Column(JSONB, default=dict, nullable=False)
    # Security test 2026-09-02, finding 6: same FK-without-action class —
    # keep the automation, orphan it gracefully.
    owner_id = Column(String, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    version = Column(Integer, default=1, nullable=False)
    consent_critical = Column(Boolean, default=False, nullable=False)
    last_run_at = Column(DateTime, nullable=True)
    last_run_status = Column(String(20), default="")
    run_count = Column(Integer, default=0, nullable=False)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
    updated_at = Column(DateTime, server_default=func.now(), nullable=False)


class PlaybookRunV2(Base):
    __tablename__ = "pb_runs_v2"

    id = Column(String, primary_key=True)
    automation_id = Column(
        String, ForeignKey("pb_automations.id", ondelete="CASCADE"), nullable=False
    )
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    trigger_type = Column(String(30), default="manual", nullable=False)
    trigger_data = Column(JSONB, default=dict)
    status = Column(String(20), default="pending", nullable=False)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    error = Column(Text, nullable=True)
    steps_log = Column(JSONB, default=list)
    triggered_by = Column(String(100), default="manual")
    context = Column(JSONB, default=dict)
    created_at = Column(DateTime, server_default=func.now(), nullable=False)
