"""license_tokens: verified signed license tokens (ФТ-5)

Revision ID: 092
Revises: 091
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = "092"
down_revision = "091"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "license_tokens",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column(
            "org_id",
            sa.String(),
            sa.ForeignKey("organizations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("raw_token", sa.String(), nullable=False),
        sa.Column("fingerprint", sa.String(), nullable=False),
        sa.Column("tier", sa.String(), nullable=False),
        sa.Column("features", JSONB, nullable=False, server_default="[]"),
        sa.Column("verified_at", sa.String(), nullable=False),
        sa.Column("expires_at", sa.String(), nullable=False),
    )
    op.create_index("ix_license_tokens_org_id", "license_tokens", ["org_id"])


def downgrade() -> None:
    op.drop_index("ix_license_tokens_org_id", table_name="license_tokens")
    op.drop_table("license_tokens")
