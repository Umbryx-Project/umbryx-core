"""RBAC restructure: org-scoped projects, project_teams, member source, unified global role

Revision ID: 030
Revises: 029
"""
revision = "030"
down_revision = "029"

from alembic import op
import sqlalchemy as sa


def upgrade() -> None:
    op.add_column("projects", sa.Column("org_id", sa.String(), nullable=True))
    op.create_foreign_key("fk_projects_org_id", "projects", "organizations", ["org_id"], ["id"], ondelete="SET NULL")

    op.add_column("project_members", sa.Column("source", sa.String(), nullable=False, server_default="direct"))

    op.add_column("team_members", sa.Column("default_project_role", sa.String(), nullable=False, server_default="viewer"))

    op.create_table(
        "project_teams",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("project_id", sa.String(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("team_id", sa.String(), sa.ForeignKey("teams.id", ondelete="CASCADE"), nullable=False),
        sa.Column("attached_at", sa.String(), nullable=False),
        sa.Column("attached_by", sa.String(), nullable=True),
    )
    op.create_index("ix_project_teams_project", "project_teams", ["project_id"])
    op.create_index("ix_project_teams_team", "project_teams", ["team_id"])

    op.execute(
        "UPDATE users SET role = 'platform_admin' WHERE role = 'admin' OR global_role = 'platform_admin'"
    )
    op.execute(
        "UPDATE users SET role = 'user' WHERE role NOT IN ('platform_admin', 'viewer')"
    )


def downgrade() -> None:
    op.drop_table("project_teams")
    op.drop_column("project_members", "source")
    op.drop_column("team_members", "default_project_role")
    op.drop_constraint("fk_projects_org_id", "projects", type_="foreignkey")
    op.drop_column("projects", "org_id")
