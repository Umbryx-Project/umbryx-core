from sqlalchemy import Column, ForeignKey, String

from ..database import Base
from ._types import JSONB


class ProjectSnapshot(Base):
    __tablename__ = "project_snapshots"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    label = Column(String, nullable=False, default="")
    groups = Column(JSONB, nullable=False, default=list)  # ["notes","findings","hosts","graph"]
    data_json = Column(JSONB, nullable=False, default=dict)
    created_by = Column(String, nullable=False, default="")
    created_at = Column(String, nullable=False)
