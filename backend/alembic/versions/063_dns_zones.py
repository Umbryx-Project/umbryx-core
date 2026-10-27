"""dns_zones_and_records

Revision ID: 063
Revises: 062
"""
from alembic import op
import sqlalchemy as sa

revision = "063"
down_revision = "062"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    existing = set(inspector.get_table_names())

    if "dns_zones" not in existing:
        op.create_table(
            "dns_zones",
            sa.Column("id", sa.String, primary_key=True),
            sa.Column("provider_id", sa.String, sa.ForeignKey("infra_providers.id", ondelete="CASCADE"), nullable=False),
            sa.Column("zone_name", sa.String(512), nullable=False),
            sa.Column("remote_zone_id", sa.String(256), nullable=False, server_default=""),
            sa.Column("authorized", sa.Boolean, nullable=False, server_default="false"),
            sa.Column("record_count", sa.Integer, nullable=False, server_default="0"),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_dns_zones_provider_zone", "dns_zones", ["provider_id", "zone_name"])

    if "dns_records" not in existing:
        op.create_table(
            "dns_records",
            sa.Column("id", sa.String, primary_key=True),
            sa.Column("zone_id", sa.String, sa.ForeignKey("dns_zones.id", ondelete="CASCADE"), nullable=False),
            sa.Column("provider_id", sa.String, sa.ForeignKey("infra_providers.id", ondelete="CASCADE"), nullable=False),
            sa.Column("name", sa.String(512), nullable=False),
            sa.Column("record_type", sa.String(16), nullable=False, server_default="A"),
            sa.Column("value", sa.Text, nullable=False),
            sa.Column("ttl", sa.Integer, nullable=False, server_default="300"),
            sa.Column("proxied", sa.Boolean, nullable=False, server_default="false"),
            sa.Column("remote_record_id", sa.String(256), nullable=False, server_default=""),
            sa.Column("status", sa.String(32), nullable=False, server_default="active"),
            sa.Column("linked_object_type", sa.String(64), nullable=True),
            sa.Column("linked_object_id", sa.String, nullable=True),
            sa.Column("error_message", sa.Text, nullable=True),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        )
        op.create_index("ix_dns_records_zone_type", "dns_records", ["zone_id", "record_type"])
        op.create_index("ix_dns_records_linked", "dns_records", ["linked_object_type", "linked_object_id"])


def downgrade() -> None:
    op.drop_table("dns_records")
    op.drop_table("dns_zones")
