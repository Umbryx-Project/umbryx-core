from sqlalchemy import Column, ForeignKey, Integer, String, Text

from ..database import Base


class Task(Base):
    __tablename__ = "tasks"
    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False, default="")
    status = Column(String, nullable=False, default="open", server_default="open")
    assignee = Column(String, nullable=True)
    due_at = Column(String, nullable=True)
    priority = Column(String, nullable=False, default="medium", server_default="medium")
    sla_hours = Column(Integer, nullable=True)
    source = Column(String, nullable=True)
    created_by = Column(String, nullable=True)
    ts = Column(String, nullable=False)
    closed_at = Column(String, nullable=True)
    reopened_count = Column(Integer, nullable=False, default=0)
    deleted_at = Column(String, nullable=True)


class Remediation(Base):
    __tablename__ = "remediations"
    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_id = Column(String, ForeignKey("findings.id", ondelete="SET NULL"), nullable=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=False, default="")
    status = Column(String, nullable=False, default="open", server_default="open")
    owner = Column(String, nullable=True)
    sla_hours = Column(Integer, nullable=True)
    due_at = Column(String, nullable=True)
    verified_by = Column(String, nullable=True)
    verified_at = Column(String, nullable=True)
    created_by = Column(String, nullable=True)
    ts = Column(String, nullable=False)
    deleted_at = Column(String, nullable=True)


class Evidence(Base):
    __tablename__ = "evidence"
    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    kind = Column(String, nullable=False, default="file")
    filename = Column(String, nullable=False, default="")
    sha256 = Column(String, nullable=True)
    storage_ref = Column(String, nullable=True)
    size_bytes = Column(Integer, nullable=True)
    collected_by = Column(String, nullable=True)
    collected_at = Column(String, nullable=True)
    notes = Column(Text, nullable=False, default="")
    created_by = Column(String, nullable=True)
    ts = Column(String, nullable=False)


class Identity(Base):
    __tablename__ = "identities"
    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    principal = Column(String, nullable=False)
    domain = Column(String, nullable=False, default="")
    identity_type = Column(String, nullable=False, default="user")
    source = Column(String, nullable=True)
    ref_cred_id = Column(String, nullable=True)
    notes = Column(Text, nullable=False, default="")
    created_by = Column(String, nullable=True)
    ts = Column(String, nullable=False)
    deleted_at = Column(String, nullable=True)
