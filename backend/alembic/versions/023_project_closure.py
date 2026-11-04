"""add project closed_at/archived_at + decommission_reports

Revision ID: 023
Revises: 022
Create Date: 2026-06-01
"""
import sqlalchemy as sa
from alembic import op

revision = "023"
down_revision = "022"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("projects", sa.Column("closed_at", sa.String(), nullable=True))
    op.add_column("projects", sa.Column("archived_at", sa.String(), nullable=True))
    op.create_table(
        "decommission_reports",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("project_id", sa.String(), nullable=False),
        sa.Column("closed_by", sa.String(), nullable=False),
        sa.Column("closure_started_at", sa.String(), nullable=False),
        sa.Column("closure_completed_at", sa.String(), nullable=True),
        sa.Column("infra_destroyed", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("secrets_revoked", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("members_deactivated", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("export_bundle_hash", sa.String(), nullable=True),
        sa.Column("warnings", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("final_status", sa.String(), nullable=False, server_default="pending"),
        sa.Column("pdf_path", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_decommission_reports_project_id", "decommission_reports", ["project_id"])


def downgrade():
    op.drop_index("ix_decommission_reports_project_id", table_name="decommission_reports")
    op.drop_table("decommission_reports")
    op.drop_column("projects", "archived_at")
    op.drop_column("projects", "closed_at")
