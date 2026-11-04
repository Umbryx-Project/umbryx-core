from sqlalchemy import Column, String

from ..database import Base
from ._types import JSONB


class DecommissionReport(Base):
    __tablename__ = "decommission_reports"

    id = Column(String, primary_key=True)
    project_id = Column(String, nullable=False, index=True)
    closed_by = Column(String, nullable=False)
    closure_started_at = Column(String, nullable=False)
    closure_completed_at = Column(String, nullable=True)
    infra_destroyed = Column(JSONB, nullable=False, default=list)
    secrets_revoked = Column(JSONB, nullable=False, default=list)
    members_deactivated = Column(JSONB, nullable=False, default=list)
    export_bundle_hash = Column(String, nullable=True)
    warnings = Column(JSONB, nullable=False, default=list)
    final_status = Column(String, nullable=False, default="pending")
    pdf_path = Column(String, nullable=True)
