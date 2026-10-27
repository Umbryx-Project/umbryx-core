"""infra_providers: add category, connection, last_check columns

Revision ID: 055
Revises: 054
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "055"
down_revision = "054"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("infra_providers", sa.Column("category", sa.String, nullable=False, server_default="cloud"))
    op.add_column("infra_providers", sa.Column("connection", JSONB, nullable=False, server_default="{}"))
    op.add_column("infra_providers", sa.Column("last_check_ok", sa.Boolean, nullable=True))
    op.add_column("infra_providers", sa.Column("last_check_msg", sa.String, nullable=True))
    op.add_column("infra_providers", sa.Column("last_check", sa.String, nullable=True))


def downgrade() -> None:
    op.drop_column("infra_providers", "last_check")
    op.drop_column("infra_providers", "last_check_msg")
    op.drop_column("infra_providers", "last_check_ok")
    op.drop_column("infra_providers", "connection")
    op.drop_column("infra_providers", "category")
