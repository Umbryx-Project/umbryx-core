"""Add clusters table for first-class cluster model

Revision ID: 036
Revises: 035
"""
from alembic import op
import sqlalchemy as sa

revision = "036"
down_revision = "035"


def upgrade():
    op.create_table(
        "clusters",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("name", sa.String, nullable=False),
        sa.Column("provider", sa.String, nullable=False, server_default="kubernetes"),
        sa.Column("environment", sa.String, nullable=False, server_default="production"),
        sa.Column("cred_id", sa.String, nullable=True),
        sa.Column("org_id", sa.String, sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True),
        sa.Column("status", sa.String, nullable=False, server_default="unknown"),
        sa.Column("api_server", sa.String, nullable=True),
        sa.Column("meta", sa.Text, nullable=False, server_default="{}"),
        sa.Column("last_seen", sa.String, nullable=True),
        sa.Column("created_at", sa.String, nullable=False),
    )


def downgrade():
    op.drop_table("clusters")
