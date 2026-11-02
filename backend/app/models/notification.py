"""In-app notifications."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import relationship

from app.database import Base


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(String, primary_key=True)
    # Security test 2026-09-02, finding 6: no ondelete meant RESTRICT in PG
    # — deleting a user with surviving notifications 500ed. They are the
    # user's own ephemeral alerts: cascade away with the account.
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    ts = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC))
    type = Column(String, nullable=False, default="info")
    title = Column(String, nullable=False)
    body = Column(Text, nullable=True)
    link = Column(String, nullable=True)
    read = Column(Boolean, nullable=False, default=False, server_default="false")
    read_ts = Column(DateTime(timezone=True), nullable=True)
    project_id = Column(String, nullable=True)

    user = relationship("User", foreign_keys=[user_id])

    __table_args__ = (
        Index("ix_notif_user_read", "user_id", "read"),
        Index("ix_notif_user_ts", "user_id", "ts"),
    )
