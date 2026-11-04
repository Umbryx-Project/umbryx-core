"""deploy_steps table + config_hash on stack_services

Revision ID: 057
Revises: 056
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "057"
down_revision = "056"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "infra_deploy_steps",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("stack_id", sa.String, sa.ForeignKey("infra_stacks.id", ondelete="CASCADE"), nullable=False),
        sa.Column("service_id", sa.String, sa.ForeignKey("infra_stack_services.id", ondelete="CASCADE"), nullable=True),
        sa.Column("step_type", sa.String, nullable=False),
        sa.Column("step_name", sa.String, nullable=False, server_default=""),
        sa.Column("status", sa.String, nullable=False, server_default="pending"),
        sa.Column("message", sa.Text, nullable=False, server_default=""),
        sa.Column("details", JSONB, nullable=False, server_default="{}"),
        sa.Column("started_at", sa.String, nullable=True),
        sa.Column("completed_at", sa.String, nullable=True),
        sa.Column("duration_ms", sa.Integer, nullable=True),
        sa.Column("created_at", sa.String, nullable=False),
    )
    op.create_index("ix_deploy_steps_stack", "infra_deploy_steps", ["stack_id"])
    op.create_index("ix_deploy_steps_service", "infra_deploy_steps", ["service_id"])

    op.add_column("infra_stack_services", sa.Column("config_hash", sa.String, nullable=True))


def downgrade() -> None:
    op.drop_column("infra_stack_services", "config_hash")
    op.drop_index("ix_deploy_steps_service", "infra_deploy_steps")
    op.drop_index("ix_deploy_steps_stack", "infra_deploy_steps")
    op.drop_table("infra_deploy_steps")
