from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Text

from ..database import Base
from ._types import pg_array as ARRAY


class Note(Base):
    __tablename__ = "notes"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String, nullable=False)
    phase = Column(String, nullable=False, default="recon")
    tags = Column(ARRAY(String), nullable=False, default=[])
    content = Column(Text, nullable=False, default="")
    ts = Column(String, nullable=False)
    starred = Column(Boolean, nullable=False, default=False)
    version = Column(Integer, nullable=False, default=0)
    deleted_at = Column(String, nullable=True)
    # Optional: a note may belong to at most one host (not many-to-many —
    # see alembic/versions/074_note_host_link.py for the decision writeup).
    # Unattached notes (host_id=None) are ordinary project-level notes.
    host_id = Column(String, ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True)


class NoteAttachment(Base):
    __tablename__ = "note_attachments"

    id = Column(String, primary_key=True)
    note_id = Column(String, ForeignKey("notes.id", ondelete="CASCADE"), nullable=False)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    filename = Column(String, nullable=False)
    content_type = Column(String, nullable=False, default="application/octet-stream")
    file_size = Column(Integer, nullable=False, default=0)
    storage_path = Column(Text, nullable=False)
    public_url = Column(Text, nullable=False)
    ts = Column(String, nullable=False)
