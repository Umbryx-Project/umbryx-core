from sqlalchemy import Boolean, Column, ForeignKey, String, Text

from ..database import Base
from ._types import JSONB


class ProjectSecret(Base):
    __tablename__ = "project_secrets"

    id = Column(String, primary_key=True)
    project_id = Column(
        String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind = Column(String, nullable=False)
    name = Column(String, nullable=False)
    value_enc = Column(Text, nullable=False, default="")
    issued_to = Column(String, nullable=True)
    issued_at = Column(String, nullable=False)
    expires_at = Column(String, nullable=True)
    revoked_at = Column(String, nullable=True)
    revoked_by = Column(String, nullable=True)
    auto_revoke_on_close = Column(Boolean, nullable=False, default=True)
    meta = Column(JSONB, nullable=False, default=dict)
