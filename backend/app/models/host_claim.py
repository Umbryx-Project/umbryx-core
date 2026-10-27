"""Deconfliction host claims."""

from sqlalchemy import Boolean, Column, ForeignKey, Index, String, Text

from ..database import Base


class HostClaim(Base):
    """An operator's declared engagement on a host.

    Soft deconfliction: a claim is advisory, not a lock — other operators
    see who is working on the host and get a warning, but nothing hard-
    blocks. Claims expire (TTL) so a crashed client can't pin a host
    forever; any repeated claim by the same operator extends it.
    """

    __tablename__ = "host_claims"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    # claim_type: host (classic) | range (CIDR block) | task (free-text scope)
    claim_type = Column(String, nullable=False, default="host")
    # host claims: host_id; range claims: CIDR in claim_target;
    # task claims: free-text description of the reserved scope
    host_id = Column(String, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=True)
    claim_target = Column(String, nullable=False, default="")
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    username = Column(String, nullable=False, default="")
    note = Column(Text, nullable=False, default="")
    active = Column(Boolean, nullable=False, default=True)
    claimed_at = Column(String, nullable=False)
    expires_at = Column(String, nullable=False)
    # When the operator pressed Release. An explicit release outranks the
    # inferred signals (jobs, workstation shell activity), so the engagement
    # map ignores any signal older than this timestamp — until the operator
    # touches the host again, which re-engages it.
    released_at = Column(String, nullable=True)

    __table_args__ = (Index("ix_host_claims_pid_host", "pid", "host_id"),)
