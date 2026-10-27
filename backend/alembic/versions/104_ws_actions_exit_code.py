"""ws_actions: exit_code for platform-originated actions

Revision ID: 104
Revises: 103
Create Date: 2026-09-26
"""

import sqlalchemy as sa

from alembic import op

revision = "104"
down_revision = "103"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "workstation_actions",
        sa.Column("exit_code", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("workstation_actions", "exit_code")
