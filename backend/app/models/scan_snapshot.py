from sqlalchemy import Column, ForeignKey, String
from sqlalchemy.dialects.postgresql import JSONB

from ..database import Base
from ._types import pg_array as ARRAY  # noqa: F401

_FK_PROJECTS_ID = "projects.id"


class ScanSnapshot(Base):
    __tablename__ = "scan_snapshots"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey(_FK_PROJECTS_ID, ondelete="CASCADE"), nullable=False, index=True)
    host_id = Column(String, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False)
    job_id = Column(String, nullable=False, default="")
    connector_key = Column(String, nullable=False, default="")
    snapshot_json = Column(JSONB, nullable=False, default=dict)
    created_at = Column(String, nullable=False)
