"""add project_invitations table

Revision ID: 018
Revises: 017
Create Date: 2026-06-01
"""
import sqlalchemy as sa
from alembic import op

revision = "018"
down_revision = "017"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "project_invitations",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("token", sa.String(), nullable=False),
        sa.Column("role", sa.String(), nullable=False, server_default="viewer"),
        sa.Column("invited_by", sa.String(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("expires_at", sa.String(), nullable=True),
        sa.Column("accepted_at", sa.String(), nullable=True),
        sa.Column("accepted_by", sa.String(), nullable=True),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default="false"),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_invitations_token", "project_invitations", ["token"], unique=True)


def downgrade():
    op.drop_index("ix_invitations_token")
    op.drop_table("project_invitations")
