"""ssl_certificates_table

Revision ID: 065
Revises: 064
"""
from alembic import op
import sqlalchemy as sa

revision = "065"
down_revision = "064"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())

    if "ssl_certificates" not in existing:
        op.create_table(
            "ssl_certificates",
            sa.Column("id", sa.String, primary_key=True),
            sa.Column("domain", sa.String(512), nullable=False),
            sa.Column("dns_provider_id", sa.String, sa.ForeignKey("infra_providers.id", ondelete="CASCADE"), nullable=False),
            sa.Column("dns_zone", sa.String(512), nullable=False),
            sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
            sa.Column("certificate_pem", sa.Text, nullable=True),
            sa.Column("chain_pem", sa.Text, nullable=True),
            sa.Column("private_key_pem", sa.Text, nullable=True),
            sa.Column("acme_account_key_pem", sa.Text, nullable=True),
            sa.Column("acme_url", sa.String(256), nullable=True),
            sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True),
            sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True),
            sa.Column("linked_object_type", sa.String(64), nullable=True),
            sa.Column("linked_object_id", sa.String, nullable=True),
            sa.Column("error_message", sa.Text, nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_ssl_certs_domain_status", "ssl_certificates", ["domain", "status"])
        op.create_index("ix_ssl_certs_dns_provider", "ssl_certificates", ["dns_provider_id"])
        op.create_index("ix_ssl_certs_linked", "ssl_certificates", ["linked_object_type", "linked_object_id"])


def downgrade() -> None:
    op.drop_table("ssl_certificates")
