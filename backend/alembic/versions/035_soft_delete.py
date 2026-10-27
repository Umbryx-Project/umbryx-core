"""Add soft-delete deleted_at column to key entities

Revision ID: 035
Revises: 034
"""
from alembic import op
import sqlalchemy as sa

revision = "035"
down_revision = "034"
branch_labels = None
depends_on = None

TABLES = ["hosts", "notes", "findings", "loots"]


def upgrade() -> None:
    for table in TABLES:
        op.add_column(table, sa.Column("deleted_at", sa.String(), nullable=True))
        op.execute(f"CREATE INDEX IF NOT EXISTS idx_{table}_deleted_at ON {table} (deleted_at)")


def downgrade() -> None:
    for table in reversed(TABLES):
        op.execute(f"DROP INDEX IF EXISTS idx_{table}_deleted_at")
        op.drop_column(table, "deleted_at")
