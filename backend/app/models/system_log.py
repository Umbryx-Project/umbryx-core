from sqlalchemy import Column, String, Text

from ..database import Base
from ._types import JSONB


class SystemLog(Base):
    __tablename__ = "system_logs"

    id = Column(String, primary_key=True)
    category = Column(String, nullable=False, index=True)
    level = Column(String, nullable=False)
    event = Column(String, nullable=False)
    message = Column(Text, nullable=False, default="")
    user_id = Column(String, nullable=True)
    project_id = Column(String, nullable=True)
    request_id = Column(String, nullable=True)
    ip = Column(String, nullable=True)
    detail = Column(JSONB, nullable=False, default=dict)
    ts = Column(String, nullable=False, index=True)
