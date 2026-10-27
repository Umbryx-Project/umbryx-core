"""loots: extracted_text — searchable document content

Revision ID: 103
Revises: 102
"""

import sqlalchemy as sa

from alembic import op

revision = "103"
down_revision = "102"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "loots",
        sa.Column("extracted_text", sa.Text(), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_column("loots", "extracted_text")
