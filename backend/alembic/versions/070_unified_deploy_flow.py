"""Unified deploy flow: integration_status + integration_payload on StackService

Revision ID: 070
Revises: 069
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "070"
down_revision = "069"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("infra_stack_services",
                  sa.Column("integration_status", sa.String, nullable=False, server_default="pending"))
    op.add_column("infra_stack_services",
                  sa.Column("integration_payload", JSONB, nullable=False, server_default="{}"))


def downgrade():
    op.drop_column("infra_stack_services", "integration_payload")
    op.drop_column("infra_stack_services", "integration_status")
