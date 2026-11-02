"""host_claims: released_at so an explicit release outranks inferred signals

Revision ID: 105
Revises: 104
Create Date: 2026-10-02
"""

import sqlalchemy as sa

from alembic import op

revision = "105"
down_revision = "104"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "host_claims",
        sa.Column("released_at", sa.String(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("host_claims", "released_at")
