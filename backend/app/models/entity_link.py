from sqlalchemy import Column, String, Text

from ..database import Base


class EntityLink(Base):
    __tablename__ = "entity_links"

    id = Column(String, primary_key=True)
    pid = Column(String, nullable=False, index=True)
    src_type = Column(String, nullable=False)
    src_id = Column(String, nullable=False)
    dst_type = Column(String, nullable=False)
    dst_id = Column(String, nullable=False)
    link_type = Column(String, nullable=False, default="relates_to")
    comment = Column(Text, nullable=False, default="")
    created_by = Column(String, nullable=True)
    ts = Column(String, nullable=False)
    deleted_at = Column(String, nullable=True)
