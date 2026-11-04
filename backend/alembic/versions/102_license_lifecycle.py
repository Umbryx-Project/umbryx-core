"""instance_license_state: revoked_at, notified_stage — license lifecycle (active/grace/wind-down)

Revision ID: 102
Revises: 101
"""

import sqlalchemy as sa

from alembic import op

revision = "102"
down_revision = "101"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("instance_license_state", sa.Column("revoked_at", sa.String(), nullable=True))
    op.add_column("instance_license_state", sa.Column("notified_stage", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("instance_license_state", "notified_stage")
    op.drop_column("instance_license_state", "revoked_at")
