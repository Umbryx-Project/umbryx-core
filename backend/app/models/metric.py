from sqlalchemy import Column, String

from ..database import Base
from ._types import JSONB


class MetricSnapshot(Base):
    __tablename__ = "metric_snapshots"
    id = Column(String, primary_key=True)
    pid = Column(String, nullable=True, index=True)
    scope = Column(String, nullable=False, default="local")
    metric_key = Column(String, nullable=False)
    value = Column(String, nullable=False, default="0")
    dims = Column(JSONB, nullable=False, default=dict)
    captured_at = Column(String, nullable=False)
