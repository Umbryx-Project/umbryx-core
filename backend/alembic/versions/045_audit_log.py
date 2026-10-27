"""audit_log table

Revision ID: 045
Revises: 044
"""
import sqlalchemy as sa
from alembic import op

revision = "045"
down_revision = "044"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_log",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("actor_id", sa.String(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("actor_name", sa.String(), nullable=True),
        sa.Column("action", sa.String(), nullable=False),
        sa.Column("target_type", sa.String(), nullable=True),
        sa.Column("target_id", sa.String(), nullable=True),
        sa.Column("project_id", sa.String(), nullable=True),
        sa.Column("detail", sa.Text(), nullable=True),
        sa.Column("ip_address", sa.String(), nullable=True),
    )
    op.create_index("ix_audit_project_ts", "audit_log", ["project_id", "ts"])
    op.create_index("ix_audit_actor_ts", "audit_log", ["actor_id", "ts"])
    op.create_index("ix_audit_action_ts", "audit_log", ["action", "ts"])


def downgrade() -> None:
    op.drop_index("ix_audit_action_ts")
    op.drop_index("ix_audit_actor_ts")
    op.drop_index("ix_audit_project_ts")
    op.drop_table("audit_log")
