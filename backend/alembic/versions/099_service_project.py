"""stack services: per-service project override (multi-engagement clusters)

Revision ID: 099
Revises: 098
"""

import sqlalchemy as sa

from alembic import op

revision = "099"
down_revision = "098"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "infra_stack_services",
        sa.Column("project_id", sa.String(), nullable=True),
    )
    op.create_index(
        "ix_infra_stack_services_project_id", "infra_stack_services", ["project_id"]
    )


def downgrade() -> None:
    op.drop_index("ix_infra_stack_services_project_id", table_name="infra_stack_services")
    op.drop_column("infra_stack_services", "project_id")
