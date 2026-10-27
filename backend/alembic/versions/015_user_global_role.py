"""add global_role column to users

Revision ID: 015
Revises: 014
Create Date: 2026-06-01
"""
import sqlalchemy as sa
from alembic import op

revision = "015"
down_revision = "014"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "users",
        sa.Column("global_role", sa.String(), nullable=False, server_default="regular"),
    )
    op.execute(
        "UPDATE users SET global_role = 'platform_admin' WHERE role = 'admin'"
    )


def downgrade():
    op.drop_column("users", "global_role")
