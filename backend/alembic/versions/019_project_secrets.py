"""add project_secrets table

Revision ID: 019
Revises: 018
Create Date: 2026-06-01
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "019"
down_revision = "018"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "project_secrets",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("value_enc", sa.Text(), nullable=False, server_default=""),
        sa.Column("issued_to", sa.String(), nullable=True),
        sa.Column("issued_at", sa.String(), nullable=False),
        sa.Column("expires_at", sa.String(), nullable=True),
        sa.Column("revoked_at", sa.String(), nullable=True),
        sa.Column("revoked_by", sa.String(), nullable=True),
        sa.Column("auto_revoke_on_close", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("meta", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_project_secrets_project_id", "project_secrets", ["project_id"])


def downgrade():
    op.drop_index("ix_project_secrets_project_id")
    op.drop_table("project_secrets")
