from sqlalchemy import Column, Integer, String

from ..database import Base
from ._types import JSONB


class SyncState(Base):
    __tablename__ = "sync_state"

    id = Column(String, primary_key=True)
    instance_id = Column(String, nullable=False)
    entity_type = Column(String, nullable=False)
    entity_id = Column(String, nullable=False)
    local_version = Column(Integer, nullable=False, default=0)
    remote_version = Column(Integer, nullable=False, default=0)
    last_synced_at = Column(String, nullable=True)
    status = Column(String, nullable=False, default="in_sync")
    origin_instance = Column(String, nullable=True)
    pid = Column(String, nullable=True, index=True)


class ConflictRecord(Base):
    __tablename__ = "conflict_records"

    id = Column(String, primary_key=True)
    entity_type = Column(String, nullable=False)
    entity_id = Column(String, nullable=False)
    local_payload = Column(JSONB, nullable=False, default=dict)
    remote_payload = Column(JSONB, nullable=False, default=dict)
    detected_at = Column(String, nullable=False)
    resolution = Column(String, nullable=False, default="pending")
    resolved_by = Column(String, nullable=True)
    resolved_at = Column(String, nullable=True)
    pid = Column(String, nullable=True, index=True)


class SyncEvent(Base):
    __tablename__ = "sync_events"

    id = Column(String, primary_key=True)
    seq = Column(Integer, nullable=False)
    instance_id = Column(String, nullable=False)
    entity_type = Column(String, nullable=False)
    entity_id = Column(String, nullable=False)
    op = Column(String, nullable=False)
    payload_hash = Column(String, nullable=True)
    signature = Column(String, nullable=True)
    ts = Column(String, nullable=False)
    pid = Column(String, nullable=True, index=True)
    payload = Column(JSONB, nullable=True)
