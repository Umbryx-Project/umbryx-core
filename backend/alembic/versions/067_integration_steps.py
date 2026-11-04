"""integration_steps on stack_services

Revision ID: 067
Revises: 066
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "067"
down_revision = "066"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("infra_stack_services",
                  sa.Column("integration_steps", JSONB, nullable=False, server_default="{}"))


def downgrade() -> None:
    op.drop_column("infra_stack_services", "integration_steps")
