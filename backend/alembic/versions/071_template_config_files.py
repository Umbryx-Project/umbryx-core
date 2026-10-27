"""Add default_config_files to ServiceTemplate

Revision ID: 071
Revises: 070
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "071"
down_revision = "070"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("infra_service_templates",
                  sa.Column("default_config_files", JSONB, nullable=False, server_default="[]"))


def downgrade():
    op.drop_column("infra_service_templates", "default_config_files")
