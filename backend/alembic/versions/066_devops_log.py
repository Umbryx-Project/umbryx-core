"""devops_log table

Revision ID: 066
Revises: 065
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "066"
down_revision = "065"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "infra_devops_log",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("stack_id", sa.String, sa.ForeignKey("infra_stacks.id", ondelete="CASCADE"), nullable=True),
        sa.Column("service_id", sa.String, nullable=True),
        sa.Column("provider_id", sa.String, nullable=True),
        sa.Column("level", sa.String, nullable=False, server_default="info"),
        sa.Column("category", sa.String, nullable=False, server_default="infra"),
        sa.Column("message", sa.Text, nullable=False),
        sa.Column("details", JSONB, nullable=False, server_default="{}"),
        sa.Column("actor", sa.String, nullable=True),
        sa.Column("created_at", sa.String, nullable=False),
    )
    op.create_index("ix_devops_log_stack", "infra_devops_log", ["stack_id"])
    op.create_index("ix_devops_log_level", "infra_devops_log", ["level"])
    op.create_index("ix_devops_log_category", "infra_devops_log", ["category"])
    op.create_index("ix_devops_log_created", "infra_devops_log", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_devops_log_created", "infra_devops_log")
    op.drop_index("ix_devops_log_category", "infra_devops_log")
    op.drop_index("ix_devops_log_level", "infra_devops_log")
    op.drop_index("ix_devops_log_stack", "infra_devops_log")
    op.drop_table("infra_devops_log")
