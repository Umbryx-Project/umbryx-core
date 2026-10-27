"""proxy pool: egress proxy endpoints + routing rules

Revision ID: 090
Revises: 089
"""

import sqlalchemy as sa
from alembic import op

from app.models._types import pg_array

revision = "090"
down_revision = "089"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "proxy_endpoints",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("scheme", sa.String(), nullable=False),
        sa.Column("host", sa.String(), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(), nullable=True),
        sa.Column("password_enc", sa.String(), nullable=True),
        sa.Column("tags", pg_array(sa.String()), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("last_check_at", sa.String(), nullable=True),
        sa.Column("last_ok", sa.Boolean(), nullable=True),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
    )
    op.create_table(
        "proxy_routes",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("category", sa.String(), nullable=False),
        sa.Column("target_ref", sa.String(), nullable=True),
        sa.Column("proxy_tags", pg_array(sa.String()), nullable=True),
        sa.Column("policy", sa.String(), nullable=False, server_default="round_robin"),
        sa.Column("failure_mode", sa.String(), nullable=False, server_default="fail_open"),
        sa.Column("priority", sa.Integer(), nullable=False, server_default="100"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.String(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("proxy_routes")
    op.drop_table("proxy_endpoints")
