"""add installed_plugins table

Revision ID: 021
Revises: 020
Create Date: 2026-06-01
"""
import sqlalchemy as sa
from alembic import op

revision = "021"
down_revision = "020"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "installed_plugins",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("version", sa.String(), nullable=False, server_default="0.0.0"),
        sa.Column("api_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("source", sa.String(), nullable=False, server_default="uploaded"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("bundle_path", sa.String(), nullable=True),
        sa.Column("manifest", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("permissions", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("installed_at", sa.String(), nullable=False),
        sa.Column("installed_by", sa.String(), nullable=True),
        sa.Column("signature", sa.String(), nullable=True),
        sa.Column("error", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade():
    op.drop_table("installed_plugins")
