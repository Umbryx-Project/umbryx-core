from sqlalchemy import Column, ForeignKey, Integer, String

from ..database import Base
from ._types import JSONB

_FK_PROJECTS_ID = "projects.id"


class FirewallConfigUpload(Base):
    __tablename__ = "firewall_config_uploads"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey(_FK_PROJECTS_ID, ondelete="CASCADE"), nullable=False, index=True)
    host_id = Column(String, ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True)
    vendor = Column(String, nullable=False)
    hostname_in_config = Column(String, nullable=False, default="")
    # Encrypted-at-rest storage key (core/secure_files.py) — never the raw config path.
    storage_key = Column(String, nullable=False, default="")
    # Normalized ParsedConfig as dict, secrets already stripped (see
    # core/firewall_enrich.py::parsed_config_to_safe_dict).
    parsed_json = Column(JSONB, nullable=False, default=dict)
    rule_count = Column(Integer, nullable=False, default=0)
    uploaded_by = Column(String, nullable=False, default="")
    ts = Column(String, nullable=False)
    job_id = Column(String, nullable=False, default="")
