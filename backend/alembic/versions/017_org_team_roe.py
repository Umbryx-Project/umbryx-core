"""add organizations, teams, project_roe tables

Revision ID: 017
Revises: 016
Create Date: 2026-06-01
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "017"
down_revision = "016"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "organizations",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("slug", sa.String(), nullable=False),
        sa.Column("plan", sa.String(), nullable=False, server_default="free"),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug"),
    )
    op.create_table(
        "organization_members",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("org_id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("role", sa.String(), nullable=False, server_default="member"),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_org_members_org_id", "organization_members", ["org_id"])
    op.create_index("ix_org_members_user_id", "organization_members", ["user_id"])
    op.create_table(
        "teams",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("org_id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_teams_org_id", "teams", ["org_id"])
    op.create_table(
        "team_members",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("team_id", sa.String(), nullable=False),
        sa.Column("user_id", sa.String(), nullable=False),
        sa.Column("role", sa.String(), nullable=False, server_default="member"),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_team_members_team_id", "team_members", ["team_id"])
    op.create_index("ix_team_members_user_id", "team_members", ["user_id"])
    op.create_table(
        "project_roe",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("allowed_activities", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("forbidden_activities", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("work_hours_start", sa.String(), nullable=True),
        sa.Column("work_hours_end", sa.String(), nullable=True),
        sa.Column("timezone", sa.String(), nullable=False, server_default="UTC"),
        sa.Column("max_scan_rate", sa.String(), nullable=True),
        sa.Column("requires_approval", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("emergency_contacts", postgresql.JSONB(), nullable=False, server_default="[]"),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.Column("updated_by", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_project_roe_project_id", "project_roe", ["project_id"], unique=True)


def downgrade():
    op.drop_index("ix_project_roe_project_id")
    op.drop_table("project_roe")
    op.drop_index("ix_team_members_user_id")
    op.drop_index("ix_team_members_team_id")
    op.drop_table("team_members")
    op.drop_index("ix_teams_org_id")
    op.drop_table("teams")
    op.drop_index("ix_org_members_user_id")
    op.drop_index("ix_org_members_org_id")
    op.drop_table("organization_members")
    op.drop_table("organizations")
