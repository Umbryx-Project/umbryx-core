"""organization_plans: license_offline + last_heartbeat_ok_at (ФТ-6)

Revision ID: 093
Revises: 092
"""

import sqlalchemy as sa
from alembic import op

revision = "093"
down_revision = "092"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "organization_plans",
        sa.Column("license_offline", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "organization_plans",
        sa.Column("last_heartbeat_ok_at", sa.String(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("organization_plans", "last_heartbeat_ok_at")
    op.drop_column("organization_plans", "license_offline")
