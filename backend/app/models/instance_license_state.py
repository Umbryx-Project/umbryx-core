from sqlalchemy import Boolean, Column, Integer, String

from ..database import Base


class InstanceLicenseState(Base):
    """Singleton row (id is always "instance") holding instance-wide
    licensing state that isn't itself part of a LicenseToken: the delivery
    channel choice and the online heartbeat's grace-period clock. See
    core/license.py's module docstring — licensing is per self-hosted
    instance, not per Organization."""

    __tablename__ = "instance_license_state"

    id = Column(String, primary_key=True)
    license_offline = Column(Boolean, nullable=False, default=False)
    last_heartbeat_ok_at = Column(String, nullable=True)
    # Longest audit retention any applied license ever granted (-1 =
    # unlimited). The retention job never deletes below this, so a lapsed
    # or downgraded license can't destroy history written under a longer one.
    retention_floor_days = Column(Integer, nullable=True)
    # Set when the License Server answers a heartbeat with "no active
    # license" — counts as the license ending at that moment, so the normal
    # grace period applies instead of an instant cut-off.
    revoked_at = Column(String, nullable=True)
    # Last lifecycle notification stage sent to admins (dedupes the hourly
    # reconciliation pass — see core/license_state.py).
    notified_stage = Column(String, nullable=True)
    updated_at = Column(String, nullable=False)
