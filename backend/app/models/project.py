from sqlalchemy import Boolean, Column, ForeignKey, String, Text

from ..database import Base
from ._types import JSONB


class Project(Base):
    __tablename__ = "projects"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    status = Column(String, nullable=False, default="active")
    ip = Column(String, nullable=False, default="")
    os = Column(String, nullable=False, default="Linux")
    added = Column(String, nullable=False)
    description = Column(Text, nullable=False, default="")
    webhook_token = Column(String, nullable=False, default="")
    closed_at = Column(String, nullable=True)
    archived_at = Column(String, nullable=True)
    org_id = Column(String, ForeignKey("organizations.id", ondelete="SET NULL"), nullable=True)
    intensity_profile = Column(String, nullable=False, default="normal")
    env_vars = Column(JSONB, nullable=False, default=dict)


class ProjectMember(Base):
    __tablename__ = "project_members"

    id = Column(String, primary_key=True)
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    role = Column(String, nullable=False, default="viewer")
    source = Column(String, nullable=False, default="direct")
    created_at = Column(String, nullable=False)
    created_by = Column(String, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)


class ProjectTeam(Base):
    __tablename__ = "project_teams"

    id = Column(String, primary_key=True)
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    team_id = Column(String, ForeignKey("teams.id", ondelete="CASCADE"), nullable=False)
    attached_at = Column(String, nullable=False)
    attached_by = Column(String, nullable=True)


class ProjectInvitation(Base):
    __tablename__ = "project_invitations"

    id = Column(String, primary_key=True)
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    token = Column(String, nullable=False, unique=True, index=True)
    role = Column(String, nullable=False, default="viewer")
    invited_by = Column(String, nullable=False)
    created_at = Column(String, nullable=False)
    expires_at = Column(String, nullable=True)
    accepted_at = Column(String, nullable=True)
    accepted_by = Column(String, nullable=True)
    revoked = Column(Boolean, nullable=False, default=False)
