"""Add pid column to sync_state, conflict_records, sync_events.

Revision ID: 042
Revises: 041
"""
from alembic import op
import sqlalchemy as sa

revision = "042"
down_revision = "041"


def upgrade():
    op.add_column("sync_state", sa.Column("pid", sa.String, nullable=True))
    op.add_column("conflict_records", sa.Column("pid", sa.String, nullable=True))
    op.add_column("sync_events", sa.Column("pid", sa.String, nullable=True))


def downgrade():
    op.drop_column("sync_events", "pid")
    op.drop_column("conflict_records", "pid")
    op.drop_column("sync_state", "pid")
