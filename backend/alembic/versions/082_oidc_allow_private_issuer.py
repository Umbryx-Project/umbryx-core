"""OIDC providers: allow_private_issuer opt-out from the SSRF guard

Revision ID: 082
Revises: 081

Self-hosted IdPs on an internal/split-horizon network (e.g. a corporate
GitLab reachable only via LAN DNS) resolve their issuer to an RFC1918
address — core.ssrf_guard blocks that by design (see
docs/modules/OIDC_SSO_SETUP.md's troubleshooting table). That's the right
default for a multi-tenant deployment: an org admin choosing an issuer is
not a trusted-enough boundary to let them point the platform's outbound
requests at arbitrary internal addresses (SSRF into another tenant's
network, cloud metadata endpoints, etc).

allow_private_issuer is additive, defaults false, and — enforced at the
API layer (routers/oidc_admin.py), not here — can only be set by a
platform_admin, not by the org admin who otherwise owns this row.
Confirmed with the product owner 2026-09-08 while wiring up a real
self-hosted GitLab OIDC test against the HA cluster.
"""

import sqlalchemy as sa
from alembic import op

revision = "082"
down_revision = "081"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "oidc_providers",
        sa.Column("allow_private_issuer", sa.Boolean(), nullable=False, server_default="false"),
    )


def downgrade() -> None:
    op.drop_column("oidc_providers", "allow_private_issuer")
