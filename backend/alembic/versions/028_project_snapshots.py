"""project_snapshots table

Revision ID: 028
Revises: 027
Create Date: 2026-06-04
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "028"
down_revision = "027"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "project_snapshots",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("pid", sa.String, sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("label", sa.String, nullable=False, server_default=""),
        sa.Column("groups", JSONB, nullable=False, server_default="[]"),
        sa.Column("data_json", JSONB, nullable=False, server_default="{}"),
        sa.Column("created_by", sa.String, nullable=False, server_default=""),
        sa.Column("created_at", sa.String, nullable=False),
    )
    op.create_index("ix_project_snapshots_pid", "project_snapshots", ["pid"])


def downgrade():
    op.drop_index("ix_project_snapshots_pid", "project_snapshots")
    op.drop_table("project_snapshots")
