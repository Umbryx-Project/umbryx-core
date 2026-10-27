from sqlalchemy import Column, ForeignKey, Integer, String

from ..database import Base
from ._types import JSONB


class OrganizationPlan(Base):
    __tablename__ = "organization_plans"

    id = Column(String, primary_key=True)
    org_id = Column(
        String, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, unique=True
    )
    tier = Column(String, nullable=False, default="free")
    max_members = Column(Integer, nullable=False, default=3)
    max_infra_instances = Column(Integer, nullable=False, default=1)
    max_workstations = Column(Integer, nullable=False, default=0)
    # ФТ-3 (docs/modules/LICENSING_TZ.md): -1 = custom/unlimited (Enterprise
    # only) — the retention cleanup job (core/audit_retention.py) skips it.
    retention_days = Column(Integer, nullable=False, default=30)
    features = Column(JSONB, nullable=False, default=list)
    stripe_customer_id = Column(String, nullable=True)
    stripe_subscription_id = Column(String, nullable=True)
    created_at = Column(String, nullable=False)
    updated_at = Column(String, nullable=False)
