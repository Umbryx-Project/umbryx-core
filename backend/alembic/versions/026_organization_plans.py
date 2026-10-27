"""add organization_plans table

Revision ID: 026
Revises: 025
Create Date: 2026-06-02
"""
import sqlalchemy as sa
from alembic import op

revision = "026"
down_revision = "025"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "organization_plans",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("org_id", sa.String(), nullable=False),
        sa.Column("tier", sa.String(), nullable=False, server_default="free"),
        sa.Column("max_members", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("max_infra_instances", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("max_workstations", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("features", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("stripe_customer_id", sa.String(), nullable=True),
        sa.Column("stripe_subscription_id", sa.String(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("updated_at", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["org_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("org_id"),
    )


def downgrade():
    op.drop_table("organization_plans")
