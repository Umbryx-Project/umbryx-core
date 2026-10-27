"""firewall_config_uploads table

Revision ID: 072
Revises: 071
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "072"
down_revision = "071"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "firewall_config_uploads",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("pid", sa.String, sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("host_id", sa.String, sa.ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True),
        sa.Column("vendor", sa.String, nullable=False),
        sa.Column("hostname_in_config", sa.String, nullable=False, server_default=""),
        sa.Column("storage_key", sa.String, nullable=False, server_default=""),
        sa.Column("parsed_json", JSONB, nullable=False, server_default="{}"),
        sa.Column("rule_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("uploaded_by", sa.String, nullable=False, server_default=""),
        sa.Column("ts", sa.String, nullable=False),
        sa.Column("job_id", sa.String, nullable=False, server_default=""),
    )
    op.create_index("ix_fwconfig_pid", "firewall_config_uploads", ["pid"])
    op.create_index("ix_fwconfig_host", "firewall_config_uploads", ["host_id"])


def downgrade() -> None:
    op.drop_index("ix_fwconfig_host", table_name="firewall_config_uploads")
    op.drop_index("ix_fwconfig_pid", table_name="firewall_config_uploads")
    op.drop_table("firewall_config_uploads")
