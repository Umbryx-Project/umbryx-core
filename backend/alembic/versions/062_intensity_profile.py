"""add intensity_profile to projects

Revision ID: 062
Revises: 061
"""
from alembic import op
import sqlalchemy as sa

revision = "062"
down_revision = "061"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("projects", sa.Column("intensity_profile", sa.String, nullable=False, server_default="normal"))


def downgrade() -> None:
    op.drop_column("projects", "intensity_profile")
