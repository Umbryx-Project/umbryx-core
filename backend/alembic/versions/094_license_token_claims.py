"""license_tokens: full claims column for anti-tamper reconciliation (ФТ-8)

Revision ID: 094
Revises: 093
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "094"
down_revision = "093"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "license_tokens",
        sa.Column("claims", JSONB, nullable=False, server_default="{}"),
    )


def downgrade() -> None:
    op.drop_column("license_tokens", "claims")
