"""Licensing is per-instance, not per-org — schema correction

Revision ID: 098
Revises: 097

The org-scoped licensing design (ФТ-4/5/6/8, revisions 092-094) was wrong:
a self-hosted install is licensed as a whole, not per internal
Organization (an MSSP-style install can have several Organizations for
different clients, all sharing one license). This migration:

  - drops license_tokens.org_id (was a FK + index) — one instance-wide
    ledger now, no org dimension;
  - drops organization_plans.license_offline / last_heartbeat_ok_at —
    those are instance-wide settings, not per-org;
  - creates instance_license_state, a singleton table holding exactly
    those two instance-wide settings instead.

No data migration for existing license_tokens/organization_plans rows:
this feature was merged and deployed for under a day with no real
customer license ever issued against it (placeholder keypair only, per
core/license.py's docstring) — there is nothing meaningful to carry
forward.
"""

import sqlalchemy as sa
from alembic import op

revision = "098"
down_revision = "097"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_index("ix_license_tokens_org_id", table_name="license_tokens")
    op.drop_constraint("license_tokens_org_id_fkey", "license_tokens", type_="foreignkey")
    op.drop_column("license_tokens", "org_id")

    op.drop_column("organization_plans", "license_offline")
    op.drop_column("organization_plans", "last_heartbeat_ok_at")

    op.create_table(
        "instance_license_state",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("license_offline", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("last_heartbeat_ok_at", sa.String(), nullable=True),
        sa.Column("updated_at", sa.String(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("instance_license_state")
    op.add_column(
        "organization_plans",
        sa.Column("last_heartbeat_ok_at", sa.String(), nullable=True),
    )
    op.add_column(
        "organization_plans",
        sa.Column("license_offline", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("license_tokens", sa.Column("org_id", sa.String(), nullable=True))
    op.create_foreign_key(
        "license_tokens_org_id_fkey",
        "license_tokens",
        "organizations",
        ["org_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_index("ix_license_tokens_org_id", "license_tokens", ["org_id"])
