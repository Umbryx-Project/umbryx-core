"""
CoreObject — universal object model table.

Stores module-defined objects in a single polymorphic table.
Each row has a ``type`` (registered via manifest), ``project_id`` (optional),
and a ``data`` JSONB column holding the schema-driven fields.

This lets modules define new object types without creating their own tables.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base
from ._types import JSONB


class CoreObject(Base):
    __tablename__ = "core_objects"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    type: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    module_id: Mapped[str] = mapped_column(String(128), nullable=False)
    # Nullable by design: modules_api distinguishes project-scoped objects
    # from platform-global ones (admin-only mutation) — see
    # test_modules_api_objects_authz.py. The IOC tracker always writes a
    # concrete project_id (audit 2026-08-31, finding 4.1.5).
    project_id: Mapped[str | None] = mapped_column(
        String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=True, index=True
    )
    name: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="active")
    data: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    relations: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )
    created_by: Mapped[str | None] = mapped_column(String, nullable=True)

    __table_args__ = (
        Index("ix_core_objects_type_project", "type", "project_id"),
        Index("ix_core_objects_status", "status"),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "type": self.type,
            "module_id": self.module_id,
            "project_id": self.project_id,
            "name": self.name,
            "status": self.status,
            "data": self.data or {},
            "relations": self.relations or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "created_by": self.created_by,
        }
