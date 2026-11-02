"""instance_license_state: retention_floor_days — longest audit retention ever licensed

Revision ID: 101
Revises: 100
"""

import sqlalchemy as sa

from alembic import op

revision = "101"
down_revision = "100"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "instance_license_state",
        sa.Column("retention_floor_days", sa.Integer(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("instance_license_state", "retention_floor_days")
