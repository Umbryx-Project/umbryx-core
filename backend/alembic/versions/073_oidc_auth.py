"""OIDC SSO: org-scoped providers, linked identities, transient auth state

Revision ID: 073
Revises: 072
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "073"
down_revision = "072"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("email", sa.String, nullable=True))
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "oidc_providers",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column(
            "org_id", sa.String, sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("name", sa.String, nullable=False),
        sa.Column("issuer_url", sa.String, nullable=False),
        sa.Column("client_id", sa.String, nullable=False),
        sa.Column("client_secret", sa.String, nullable=False),
        sa.Column("scopes", JSONB, nullable=False, server_default='["openid", "email", "profile"]'),
        sa.Column("authorization_endpoint", sa.String, nullable=False, server_default=""),
        sa.Column("token_endpoint", sa.String, nullable=False, server_default=""),
        sa.Column("userinfo_endpoint", sa.String, nullable=False, server_default=""),
        sa.Column("jwks_uri", sa.String, nullable=False, server_default=""),
        sa.Column("claim_mapping", JSONB, nullable=False, server_default='{"email": "email", "name": "name", "groups": "groups"}'),
        sa.Column("role_mapping", JSONB, nullable=False, server_default="{}"),
        sa.Column("default_role", sa.String, nullable=False, server_default="viewer"),
        sa.Column("jit_provisioning_enabled", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("require_platform_mfa", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("email_domain", sa.String, nullable=False, server_default=""),
        sa.Column("enabled", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("enforced", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("last_test_login_at", sa.String, nullable=True),
        sa.Column("created_at", sa.String, nullable=False),
        sa.Column("updated_at", sa.String, nullable=False),
        sa.Column("created_by", sa.String, nullable=True),
    )
    op.create_index("ix_oidc_providers_org", "oidc_providers", ["org_id"])

    op.create_table(
        "oidc_identities",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column(
            "provider_id", sa.String, sa.ForeignKey("oidc_providers.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("subject", sa.String, nullable=False),
        sa.Column("user_id", sa.String, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("email_at_link_time", sa.String, nullable=False, server_default=""),
        sa.Column("linked_at", sa.String, nullable=False),
    )
    op.create_index(
        "uq_oidc_identity_provider_subject", "oidc_identities", ["provider_id", "subject"], unique=True
    )
    op.create_index("ix_oidc_identities_user", "oidc_identities", ["user_id"])

    # Transient CSRF/PKCE state for the in-flight authorization-code
    # round trip — one row per initiated login, deleted (or lazily
    # expired) on callback. A DB table rather than Redis so the flow
    # works identically with or without Redis configured.
    op.create_table(
        "oidc_auth_states",
        sa.Column("state", sa.String, primary_key=True),
        sa.Column(
            "provider_id", sa.String, sa.ForeignKey("oidc_providers.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("code_verifier", sa.String, nullable=False),
        sa.Column("nonce", sa.String, nullable=False),
        sa.Column("redirect_after", sa.String, nullable=False, server_default=""),
        sa.Column("created_at", sa.String, nullable=False),
        sa.Column("expires_at", sa.String, nullable=False),
    )
    op.create_index("ix_oidc_auth_states_provider", "oidc_auth_states", ["provider_id"])


def downgrade() -> None:
    op.drop_table("oidc_auth_states")
    op.drop_index("ix_oidc_identities_user", table_name="oidc_identities")
    op.drop_index("uq_oidc_identity_provider_subject", table_name="oidc_identities")
    op.drop_table("oidc_identities")
    op.drop_index("ix_oidc_providers_org", table_name="oidc_providers")
    op.drop_table("oidc_providers")
    op.drop_index("ix_users_email", table_name="users")
    op.drop_column("users", "email")
