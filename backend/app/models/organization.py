from sqlalchemy import Column, ForeignKey, String, Text, UniqueConstraint

from ..database import Base
from ._types import JSONB


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    slug = Column(String, nullable=False, unique=True)
    created_at = Column(String, nullable=False)


class Team(Base):
    __tablename__ = "teams"

    id = Column(String, primary_key=True)
    org_id = Column(
        String, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name = Column(String, nullable=False)
    created_at = Column(String, nullable=False)


class OrganizationMember(Base):
    __tablename__ = "organization_members"
    __table_args__ = (UniqueConstraint("org_id", "user_id", name="uq_org_member"),)

    id = Column(String, primary_key=True)
    org_id = Column(
        String, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(String, nullable=False, default="viewer")
    created_at = Column(String, nullable=False)


class TeamMember(Base):
    __tablename__ = "team_members"
    __table_args__ = (UniqueConstraint("team_id", "user_id", name="uq_team_member"),)

    id = Column(String, primary_key=True)
    team_id = Column(String, ForeignKey("teams.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role = Column(String, nullable=False, default="viewer")
    default_project_role = Column(String, nullable=False, default="viewer")
    created_at = Column(String, nullable=False)


class ProjectROE(Base):
    __tablename__ = "project_roe"

    id = Column(String, primary_key=True)
    project_id = Column(String, nullable=False, unique=True, index=True)
    allowed_activities = Column(JSONB, nullable=False, default=list)
    forbidden_activities = Column(JSONB, nullable=False, default=list)
    work_hours_start = Column(String, nullable=True)
    work_hours_end = Column(String, nullable=True)
    timezone = Column(String, nullable=False, default="UTC")
    max_scan_rate = Column(String, nullable=True)
    requires_approval = Column(JSONB, nullable=False, default=list)
    emergency_contacts = Column(JSONB, nullable=False, default=list)
    notes = Column(Text, nullable=False, default="")
    updated_at = Column(String, nullable=False)
    updated_by = Column(String, nullable=True)
