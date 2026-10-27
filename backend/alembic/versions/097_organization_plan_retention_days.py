"""organization_plans: retention_days for per-tier audit retention (ФТ-3)

Revision ID: 097
Revises: 096
"""

import sqlalchemy as sa
from alembic import op

revision = "097"
down_revision = "096"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "organization_plans",
        sa.Column("retention_days", sa.Integer(), nullable=False, server_default="30"),
    )
    op.execute("UPDATE organization_plans SET retention_days = 90 WHERE tier = 'team'")
    op.execute("UPDATE organization_plans SET retention_days = 365 WHERE tier = 'pro'")
    op.execute("UPDATE organization_plans SET retention_days = -1 WHERE tier = 'enterprise'")


def downgrade() -> None:
    op.drop_column("organization_plans", "retention_days")
