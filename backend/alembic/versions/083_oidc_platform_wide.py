"""OIDC providers: allow org_id NULL for platform-wide SSO

Revision ID: 083
Revises: 082

Product decision (2026-09-09, confirmed with the product owner): the
platform's default deployment isn't multiple independent client
organizations sharing one instance (the MSSP-SaaS case, where per-org
OIDC config and isolation genuinely matters) — it's a single company
running Umbryx internally with several teams underneath one
organization. For that shape, requiring a separate OIDC provider per org
is pure friction: there's only one org, and the natural expectation is
"our whole company signs in with our IdP, then managers sort people into
teams/roles afterward" — not "re-register an OAuth client per team."

This migration only relaxes the constraint (org_id becomes nullable);
existing org-scoped rows and behavior are untouched. A NULL org_id marks
a platform-wide provider: configurable only by a platform_admin (see
routers/oidc_platform_admin.py, not routers/oidc_admin.py), and its
JIT-provisioned users join no organization automatically — core/
oidc/flow.py skips the OrganizationMember insert and role_mapping
entirely when org_id is NULL, since there is no org to assign a role in.
"enforced" (obligatory SSO / disable passwords) is deliberately not
exposed for platform-wide providers in this pass — its blast radius for
"every user on the platform" needs its own design, not a reuse of the
per-org toggle.

The org-scoped MSSP case this replaces nothing about — routers/
oidc_admin.py's per-org CRUD is unchanged, still requires org_id, still
gates on the org's `sso` plan feature.
"""

import sqlalchemy as sa
from alembic import op

revision = "083"
down_revision = "082"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("oidc_providers", "org_id", existing_type=sa.String(), nullable=True)


def downgrade() -> None:
    # A platform-wide (org_id IS NULL) provider has no sane org to assign
    # on downgrade — delete rather than leave an invalid NOT NULL column
    # with NULLs that would break the alter itself.
    op.execute("DELETE FROM oidc_providers WHERE org_id IS NULL")
    op.alter_column("oidc_providers", "org_id", existing_type=sa.String(), nullable=False)
