"""Add user_id column to infra_events

Revision ID: 034
Revises: 033
"""
from alembic import op
import sqlalchemy as sa

revision = "034"
down_revision = "033"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "infra_events",
        sa.Column("user_id", sa.String(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("infra_events", "user_id")
