"""Service integration payload: tokens, delivery config, platform API URL

Revision ID: 069
Revises: 068
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "069"
down_revision = "068"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "infra_service_tokens",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("token_hash", sa.String, nullable=False, unique=True, index=True),
        sa.Column("service_id", sa.String, sa.ForeignKey("infra_stack_services.id", ondelete="CASCADE"), nullable=False),
        sa.Column("stack_id", sa.String, sa.ForeignKey("infra_stacks.id", ondelete="CASCADE"), nullable=False),
        sa.Column("project_id", sa.String, nullable=True),
        sa.Column("role", sa.String, nullable=False, default=""),
        sa.Column("scopes", JSONB, nullable=False, default=list),
        sa.Column("created_at", sa.String, nullable=False),
        sa.Column("last_used", sa.String, nullable=True),
        sa.Column("confirmed_at", sa.String, nullable=True),
    )

    op.add_column("infra_stack_services",
                  sa.Column("integration_delivery", JSONB, nullable=False, server_default="{}"))

    op.execute("""
        INSERT INTO global_settings (key, value)
        VALUES ('platform_api_url', '{"external": "", "internal": ""}')
        ON CONFLICT (key) DO NOTHING
    """)


def downgrade():
    op.drop_column("infra_stack_services", "integration_delivery")
    op.drop_table("infra_service_tokens")
