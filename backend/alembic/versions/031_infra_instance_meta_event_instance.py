"""add meta to infra_instances and instance_id to infra_events

Revision ID: 031
Revises: 030
Create Date: 2026-06-06
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "031"
down_revision = "030"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "infra_instances",
        sa.Column("meta", JSONB, nullable=False, server_default="{}"),
    )
    op.add_column(
        "infra_events",
        sa.Column(
            "instance_id",
            sa.String,
            sa.ForeignKey("infra_instances.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("idx_infra_event_instance", "infra_events", ["instance_id"])
    op.create_index("idx_infra_event_project", "infra_events", ["project_id"])


def downgrade() -> None:
    op.drop_index("idx_infra_event_project", "infra_events")
    op.drop_index("idx_infra_event_instance", "infra_events")
    op.drop_column("infra_events", "instance_id")
    op.drop_column("infra_instances", "meta")
