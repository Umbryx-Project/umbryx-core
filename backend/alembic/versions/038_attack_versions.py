"""Attack path versions table.

Revision ID: 038
Revises: 037
"""
from alembic import op
import sqlalchemy as sa

revision = "038"
down_revision = "037"


def upgrade():
    op.create_table(
        "attack_path_versions",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("path_id", sa.String, sa.ForeignKey("attack_paths.id", ondelete="CASCADE"), nullable=False),
        sa.Column("version", sa.Integer, nullable=False),
        sa.Column("snapshot", sa.Text, nullable=False, server_default="{}"),
        sa.Column("change_summary", sa.Text, nullable=False, server_default=""),
        sa.Column("created_by", sa.String, nullable=True),
        sa.Column("ts", sa.String, nullable=False),
    )


def downgrade():
    op.drop_table("attack_path_versions")
