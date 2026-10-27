"""scan snapshots for diffing

Revision ID: 061_scan_snapshots
Revises: 060_playbook_automation
Create Date: 2026-07-13
"""
from alembic import op
import sqlalchemy as sa

revision = "061"
down_revision = "060"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_snapshots",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("pid", sa.String, sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("host_id", sa.String, sa.ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("job_id", sa.String, nullable=False, default=""),
        sa.Column("connector_key", sa.String, nullable=False, default=""),
        sa.Column("snapshot_json", sa.dialects.postgresql.JSONB, nullable=False, default=dict),
        sa.Column("created_at", sa.String, nullable=False),
    )
    op.create_index("ix_scan_snapshots_pid", "scan_snapshots", ["pid"])
    op.create_index("ix_scan_snapshots_host_id", "scan_snapshots", ["host_id"])


def downgrade() -> None:
    op.drop_index("ix_scan_snapshots_host_id", table_name="scan_snapshots")
    op.drop_index("ix_scan_snapshots_pid", table_name="scan_snapshots")
    op.drop_table("scan_snapshots")
