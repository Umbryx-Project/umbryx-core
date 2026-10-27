"""add project_encryption_keys table

Revision ID: 020
Revises: 019
Create Date: 2026-06-01
"""
import sqlalchemy as sa
from alembic import op

revision = "020"
down_revision = "019"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "project_encryption_keys",
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("dek_enc", sa.String(), nullable=False),
        sa.Column("algorithm", sa.String(), nullable=False, server_default="fernet-aes128"),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("rotated_at", sa.String(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.PrimaryKeyConstraint("project_id"),
    )


def downgrade():
    op.drop_table("project_encryption_keys")
