"""organizations: drop the unused free-text plan column (ФТ-11)

Revision ID: 095
Revises: 094

Organization.plan was a free-text column any org owner could set through
the same CRUD API that created/updated the org, and nothing in plan
enforcement (core/plan.py's OrganizationPlan, checked by
require_plan_feature/has_feature/check_member_limit/etc.) ever read it —
see docs/modules/MONETIZATION_GAP_AUDIT.md §4 and
docs/modules/LICENSING_TZ.md ФТ-11. It was harmless today only because
nothing consumed it, but its presence (and easy confusion with the real
OrganizationPlan.tier) was a risk for future code accidentally trusting
it. Real entitlement lives in the organization_plans table.
"""

import sqlalchemy as sa
from alembic import op

revision = "095"
down_revision = "094"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_column("organizations", "plan")


def downgrade() -> None:
    op.add_column(
        "organizations",
        sa.Column("plan", sa.String(), nullable=False, server_default="free"),
    )
