"""no-op — placeholder for unified roles migration (already applied)

Revision ID: 027
Revises: 026
"""
from alembic import op

revision = "027"
down_revision = "026"
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
