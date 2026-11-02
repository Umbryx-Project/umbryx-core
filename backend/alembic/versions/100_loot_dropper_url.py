"""loots: dropper_url — public pwndrop link for generated payloads

Revision ID: 100
Revises: 099
"""

import sqlalchemy as sa

from alembic import op

revision = "100"
down_revision = "099"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("loots", sa.Column("dropper_url", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("loots", "dropper_url")
