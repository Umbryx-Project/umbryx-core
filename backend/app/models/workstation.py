from sqlalchemy import Boolean, Column, ForeignKey, String, Text

from ..database import Base
from ._types import JSONB


class WorkstationTemplate(Base):
    __tablename__ = "workstation_templates"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    kind = Column(String, nullable=False, default="docker")
    category = Column(String, nullable=False, default="linux")
    spec = Column(JSONB, nullable=False, default=dict)
    is_builtin = Column(Boolean, nullable=False, default=False, server_default="false")
    created_at = Column(String, nullable=False)


class OperatorWorkstation(Base):
    __tablename__ = "operator_workstations"

    id = Column(String, primary_key=True)
    # Pool model (2026-09-02): a workstation may exist without a project or
    # an owner — pre-provisioned pool machine, bound later via
    # WorkstationAccess. Deleting a project/orphaning a user DETACHES the
    # machine (SET NULL) instead of destroying pool infrastructure.
    project_id = Column(
        String, ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True
    )
    user_id = Column(String, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    # PlatformOps integration: both pool machines and per-project cloud
    # workstations (hetzner/kubernetes/aws) provision through an
    # InfraProvider from PlatformOps — the single credential/provider store
    # (the old per-workstation `cred_id` blob was removed; it never had a
    # working create endpoint, so there was no data to migrate).
    infra_provider_id = Column(
        String, ForeignKey("infra_providers.id", ondelete="SET NULL"), nullable=True
    )
    is_pool = Column(Boolean, nullable=False, default=False, server_default="false")
    template_id = Column(
        String, ForeignKey("workstation_templates.id", ondelete="SET NULL"), nullable=True
    )
    name = Column(String, nullable=False)
    provider = Column(String, nullable=False, default="docker", server_default="docker")
    status = Column(String, nullable=False, default="planned")
    access_address = Column(String, nullable=False, default="")
    ssh_key_id = Column(String, nullable=True)
    web_console_url = Column(String, nullable=True)
    created_at = Column(String, nullable=False)
    ready_at = Column(String, nullable=True)
    destroyed_at = Column(String, nullable=True)
    meta = Column(JSONB, nullable=False, default=dict)


class UserSshKey(Base):
    """SSH public keys owned by a user profile (2026-09-02 pool feature).

    These are the keys granted onto pool workstations' authorized_keys when
    an admin binds a machine to the user; revoking access removes the key
    line from the machine. Only PUBLIC material is stored here.
    """

    __tablename__ = "user_ssh_keys"

    id = Column(String, primary_key=True)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String, nullable=False, default="")
    public_key = Column(Text, nullable=False)
    fingerprint = Column(String, nullable=False, default="", index=True)
    created_at = Column(String, nullable=False)
    last_used_at = Column(String, nullable=True)


class WorkstationAccess(Base):
    """Who can SSH into which pool workstation, via which key.

    Multi-user by design: several users (each with their own key) may hold
    access to the same machine; revoking one doesn't touch the others.
    Grant/revoke actions are mirrored to the project timeline (when the
    machine is bound to a project) and the audit log.
    """

    __tablename__ = "workstation_access"

    id = Column(String, primary_key=True)
    workstation_id = Column(
        String,
        ForeignKey("operator_workstations.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    key_id = Column(String, ForeignKey("user_ssh_keys.id", ondelete="CASCADE"), nullable=False)
    granted_by = Column(String, nullable=True)
    granted_at = Column(String, nullable=False)
    revoked_at = Column(String, nullable=True)
    revoked_by = Column(String, nullable=True)


class InfraEvent(Base):
    __tablename__ = "infra_events"

    id = Column(String, primary_key=True)
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    workstation_id = Column(
        String, ForeignKey("operator_workstations.id", ondelete="SET NULL"), nullable=True
    )
    # Not a ForeignKey: `infra_instances` is a DB table from a removed
    # feature with no surviving ORM model, so a declared FK here can't be
    # resolved — SQLAlchemy raises NoReferencedTableError the first time
    # anything flushes an InfraEvent (discovered via a real k8s workstation
    # provisioning crash, 2026-09-04). Nothing sets this column; it's
    # always NULL in practice.
    instance_id = Column(String, nullable=True)
    user_id = Column(String, nullable=True)
    event_type = Column(String, nullable=False)
    payload = Column(JSONB, nullable=False, default=dict)
    timestamp = Column(String, nullable=False)
