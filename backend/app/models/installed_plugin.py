from sqlalchemy import Boolean, Column, Integer, String

from ..database import Base
from ._types import JSONB


class InstalledPlugin(Base):
    __tablename__ = "installed_plugins"

    id = Column(String, primary_key=True)
    version = Column(String, nullable=False, default="0.0.0")
    api_version = Column(Integer, nullable=False, default=1)
    source = Column(String, nullable=False, default="uploaded")
    enabled = Column(Boolean, nullable=False, default=True, server_default="true")
    bundle_path = Column(String, nullable=True)
    manifest = Column(JSONB, nullable=False, default=dict)
    permissions = Column(JSONB, nullable=False, default=dict)
    installed_at = Column(String, nullable=False)
    installed_by = Column(String, nullable=True)
    signature = Column(String, nullable=True)
    error = Column(String, nullable=True)
