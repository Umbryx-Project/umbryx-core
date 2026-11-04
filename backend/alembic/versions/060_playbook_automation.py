"""Playbook automation tables.

Revision ID: 060
Revises: 059
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "060"
down_revision = "059"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "pb_automations",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("pid", sa.String, sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String, nullable=False),
        sa.Column("description", sa.Text, server_default=""),
        sa.Column("enabled", sa.Boolean, server_default="false", nullable=False),
        sa.Column("definition", JSONB, server_default="{}", nullable=False),
        sa.Column("owner_id", sa.String, sa.ForeignKey("users.id"), nullable=True),
        sa.Column("version", sa.Integer, server_default="1", nullable=False),
        sa.Column("consent_critical", sa.Boolean, server_default="false", nullable=False),
        sa.Column("last_run_at", sa.DateTime, nullable=True),
        sa.Column("last_run_status", sa.String(20), server_default=""),
        sa.Column("run_count", sa.Integer, server_default="0", nullable=False),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime, server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_pb_automations_pid", "pb_automations", ["pid"])
    op.create_index("ix_pb_automations_enabled", "pb_automations", ["enabled"])

    op.create_table(
        "pb_runs_v2",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("automation_id", sa.String, sa.ForeignKey("pb_automations.id", ondelete="CASCADE"), nullable=False),
        sa.Column("pid", sa.String, sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("trigger_type", sa.String(30), server_default="manual", nullable=False),
        sa.Column("trigger_data", JSONB, server_default="{}"),
        sa.Column("status", sa.String(20), server_default="pending", nullable=False),
        sa.Column("started_at", sa.DateTime, nullable=True),
        sa.Column("finished_at", sa.DateTime, nullable=True),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("steps_log", JSONB, server_default="[]"),
        sa.Column("triggered_by", sa.String(100), server_default="manual"),
        sa.Column("context", JSONB, server_default="{}"),
        sa.Column("created_at", sa.DateTime, server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_pb_runs_v2_automation_id", "pb_runs_v2", ["automation_id"])
    op.create_index("ix_pb_runs_v2_pid", "pb_runs_v2", ["pid"])
    op.create_index("ix_pb_runs_v2_status", "pb_runs_v2", ["status"])


def downgrade() -> None:
    op.drop_index("ix_pb_runs_v2_status", "pb_runs_v2")
    op.drop_index("ix_pb_runs_v2_pid", "pb_runs_v2")
    op.drop_index("ix_pb_runs_v2_automation_id", "pb_runs_v2")
    op.drop_table("pb_runs_v2")
    op.drop_index("ix_pb_automations_enabled", "pb_automations")
    op.drop_index("ix_pb_automations_pid", "pb_automations")
    op.drop_table("pb_automations")
