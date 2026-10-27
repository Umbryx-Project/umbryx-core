"""Deconfliction host claims (soft locks preventing operator collisions).

Revision ID: 086
Revises: 085

Two operators hitting the same target silently break each other: noisy
double-scans, conflicting exploitation steps, trampled OPSEC. HostClaims
are soft, TTL-bound engagements — advisory, never blocking — combined
with a computed per-host engagement view (claims + running jobs) the UI
surfaces before anyone acts on a busy host.
"""

import sqlalchemy as sa

from alembic import op

revision = "086"
down_revision = "085"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "host_claims",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("pid", sa.String(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("host_id", sa.String(), sa.ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.String(), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("username", sa.String(), nullable=False, server_default=""),
        sa.Column("note", sa.Text(), nullable=False, server_default=""),
        sa.Column("active", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("claimed_at", sa.String(), nullable=False),
        sa.Column("expires_at", sa.String(), nullable=False),
    )
    op.create_index("ix_host_claims_pid_host", "host_claims", ["pid", "host_id"])


def downgrade() -> None:
    op.drop_index("ix_host_claims_pid_host", table_name="host_claims")
    op.drop_table("host_claims")
