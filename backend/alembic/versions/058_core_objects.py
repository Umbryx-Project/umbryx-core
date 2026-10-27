"""core_objects table for universal object model

Revision ID: 058
Revises: 057
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "058"
down_revision = "057"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "core_objects",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("type", sa.String(128), nullable=False),
        sa.Column("module_id", sa.String(128), nullable=False),
        sa.Column("project_id", sa.String, nullable=True),
        sa.Column("name", sa.String(512), nullable=False, server_default=""),
        sa.Column("status", sa.String(64), nullable=False, server_default="active"),
        sa.Column("data", JSONB, nullable=False, server_default="{}"),
        sa.Column("relations", JSONB, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String, nullable=True),
    )
    op.create_index("ix_core_objects_type", "core_objects", ["type"])
    op.create_index("ix_core_objects_project_id", "core_objects", ["project_id"])
    op.create_index("ix_core_objects_status", "core_objects", ["status"])
    op.create_index("ix_core_objects_type_project", "core_objects", ["type", "project_id"])


def downgrade() -> None:
    op.drop_index("ix_core_objects_type_project", "core_objects")
    op.drop_index("ix_core_objects_status", "core_objects")
    op.drop_index("ix_core_objects_project_id", "core_objects")
    op.drop_index("ix_core_objects_type", "core_objects")
    op.drop_table("core_objects")
