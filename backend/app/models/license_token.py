from sqlalchemy import Column, String

from ..database import Base
from ._types import JSONB


class LicenseToken(Base):
    """A verified signed license token — see core/license.py and
    docs/modules/LICENSING_TZ.md ФТ-5. One instance-wide ledger (no org_id
    — licensing is per self-hosted install, not per Organization; see
    core/license.py's module docstring), append-only: the current
    entitlement is always the row with the latest verified_at.
    """

    __tablename__ = "license_tokens"

    id = Column(String, primary_key=True)
    raw_token = Column(String, nullable=False)
    fingerprint = Column(String, nullable=False)
    tier = Column(String, nullable=False)
    features = Column(JSONB, nullable=False, default=list)
    # Full parsed claims dict, kept alongside the tier/features columns
    # above (those stay for cheap display queries). Needed for the
    # numeric limits (max_members/etc.), which a license can override
    # per-customer beyond the tier's defaults — see
    # core/plan.py's get_instance_entitlement.
    claims = Column(JSONB, nullable=False, default=dict)
    verified_at = Column(String, nullable=False)
    expires_at = Column(String, nullable=False)
