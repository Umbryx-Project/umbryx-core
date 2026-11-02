"""add dns_records table

Revision ID: 025
Revises: 024
Create Date: 2026-06-01
"""
import sqlalchemy as sa
from alembic import op

revision = "025"
down_revision = "024"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "dns_records",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("provider", sa.String(), nullable=False, server_default="manual"),
        sa.Column("zone_id", sa.String(), nullable=False, server_default=""),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("type", sa.String(), nullable=False, server_default="A"),
        sa.Column("value", sa.String(), nullable=False),
        sa.Column("ttl", sa.Integer(), nullable=False, server_default="300"),
        sa.Column("linked_to", sa.String(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("deleted_at", sa.String(), nullable=True),
        sa.Column("provider_record_id", sa.String(), nullable=True),
        sa.Column("meta", sa.JSON(), nullable=False, server_default="{}"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_dns_records_project_id", "dns_records", ["project_id"])


def downgrade():
    op.drop_index("ix_dns_records_project_id", table_name="dns_records")
    op.drop_table("dns_records")
