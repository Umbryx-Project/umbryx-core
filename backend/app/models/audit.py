"""Audit log — immutable record of all significant actions."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import Column, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import relationship

from ..database import Base


class AuditEntry(Base):
    __tablename__ = "audit_log"

    id = Column(String, primary_key=True)
    ts = Column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        index=True,
    )
    # Security test 2026-09-02, finding 6: audit entries are forensic
    # evidence — they must SURVIVE user deletion with the actor anonymized
    # (SET NULL), never block the delete and never be cascaded away.
    actor_id = Column(
        String, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    actor_name = Column(String, nullable=True)
    action = Column(String, nullable=False, index=True)
    target_type = Column(String, nullable=True, index=True)
    target_id = Column(String, nullable=True, index=True)
    project_id = Column(String, nullable=True, index=True)
    # Backfilled at write time in core/audit.log_action() — either passed
    # explicitly by org-level call sites (member/team actions) or resolved
    # from project_id for project-scoped ones. Needed for per-tier audit
    # retention (ФТ-3, docs/modules/LICENSING_TZ.md) — before this, org_id
    # only existed inside the free-text `detail` blob, not queryable.
    org_id = Column(
        String, ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True, index=True
    )
    detail = Column(Text, nullable=True)
    ip_address = Column(String, nullable=True)

    actor = relationship("User", foreign_keys=[actor_id])

    __table_args__ = (
        Index("ix_audit_project_ts", "project_id", "ts"),
        Index("ix_audit_actor_ts", "actor_id", "ts"),
        Index("ix_audit_action_ts", "action", "ts"),
        Index("ix_audit_org_ts", "org_id", "ts"),
    )
