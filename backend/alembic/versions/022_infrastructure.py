"""add infrastructure tables

Revision ID: 022
Revises: 021
Create Date: 2026-06-01
"""
import sqlalchemy as sa
from alembic import op

revision = "022"
down_revision = "021"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "infra_templates",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False, server_default="docker_compose"),
        sa.Column("spec", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("services", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("is_builtin", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("org_id", sa.String(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("created_by", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
    )
    op.create_table(
        "infra_instances",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("template_id", sa.String(), nullable=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False, server_default="planned"),
        sa.Column("params", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("resources", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("ready_at", sa.String(), nullable=True),
        sa.Column("destroyed_at", sa.String(), nullable=True),
        sa.Column("error", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["template_id"], ["infra_templates.id"], ondelete="SET NULL"),
    )
    op.create_table(
        "infra_resources",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("instance_id", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False, server_default="container"),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("provider_id", sa.String(), nullable=True),
        sa.Column("status", sa.String(), nullable=False, server_default="planned"),
        sa.Column("meta", sa.JSON(), nullable=False, server_default="{}"),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["instance_id"], ["infra_instances.id"], ondelete="CASCADE"),
    )


def downgrade():
    op.drop_table("infra_resources")
    op.drop_table("infra_instances")
    op.drop_table("infra_templates")
