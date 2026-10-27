"""custom_playbooks.org_id tenant scoping

Revision ID: 079
Revises: 078

Audit 2026-08-31, finding 3.3: CustomPlaybook had no tenant scoping — every
authenticated user could read every custom playbook (targets, TTP chains)
platform-wide. Scoping target chosen by the implementing agent from its
own analysis of how CustomPlaybook is used in the code (shared, reusable
TTP chains across a team's projects — org fits that shape better than a
single engagement/project). NOTE: initially an implementer's decision made without
product-owner sign-off; confirmed by the product owner post-hoc on
2026-09-01. The column is additive and nullable:

- org_id set    → visible to the org's members; owner/org-admin/platform-
                  admin can mutate
- org_id NULL   → personal: visible to the creator and platform admins only
                  (legacy rows without an owner match fall back to
                  platform-admin visibility)

Reversal drops the column.
"""

import sqlalchemy as sa
from alembic import op

revision = "079"
down_revision = "078"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "custom_playbooks",
        sa.Column("org_id", sa.String(), nullable=True),
    )
    op.create_index(
        "ix_custom_playbooks_org_id",
        "custom_playbooks",
        ["org_id"],
    )
    op.create_foreign_key(
        "fk_custom_playbooks_org_id",
        "custom_playbooks",
        "organizations",
        ["org_id"],
        ["id"],
        ondelete="CASCADE",
    )


def downgrade() -> None:
    op.drop_constraint("fk_custom_playbooks_org_id", "custom_playbooks", type_="foreignkey")
    op.drop_index("ix_custom_playbooks_org_id", table_name="custom_playbooks")
    op.drop_column("custom_playbooks", "org_id")
