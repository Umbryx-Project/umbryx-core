"""dns_records: replace the pre-063 table the new model never matched

Revision ID: 106
Revises: 105
Create Date: 2026-10-05

025 created a dns_records table of its own shape (project_id, provider,
type, value, …) for the old per-project DNS feature. 063 introduced the
zone-based model — models/dns.py's DnsRecord: zone_id, provider_id,
record_type, status, … — but created its table only ``if "dns_records"
not in existing``, so on any instance that had ever run 025 the legacy
table survived and the new model was mapped onto columns that do not
exist. Every DNS record endpoint then answered 500 on a freshly deployed
Enterprise build: GET /api/infra-v2/dns/records, the per-zone record
list, and record creation.

The two shapes cannot be reconciled row by row — the legacy rows carry a
project id and a free-text provider name, while the new ones hang off a
dns_zones row and an infra_providers row, and nothing in the legacy data
says which. So the legacy table is kept, renamed, rather than converted
or dropped: an operator who has records in it keeps them, and the DNS
feature starts working.
"""

import sqlalchemy as sa

from alembic import op

revision = "106"
down_revision = "105"
branch_labels = None
depends_on = None

_LEGACY_MARKER = "project_id"
_LEGACY_NAME = "dns_records_legacy"


def _columns(inspector, table: str) -> set[str]:
    return {c["name"] for c in inspector.get_columns(table)}


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if "dns_records" not in tables:
        # Nothing ran 025 here; 063 already created the zone-based table.
        return
    if _LEGACY_MARKER not in _columns(inspector, "dns_records"):
        # Already the zone-based shape.
        return
    if _LEGACY_NAME in tables:
        # A previous run of this migration got this far.
        return

    # The legacy index would keep its name across the rename and clash with
    # nothing, but it is clearer to carry the suffix too.
    op.execute("ALTER INDEX IF EXISTS ix_dns_records_project_id RENAME TO ix_dns_records_legacy_project_id")
    op.rename_table("dns_records", _LEGACY_NAME)

    op.create_table(
        "dns_records",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column(
            "zone_id",
            sa.String,
            sa.ForeignKey("dns_zones.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "provider_id",
            sa.String,
            sa.ForeignKey("infra_providers.id", ondelete="CASCADE"),
            nullable=False,
        ),
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
        # 064 added these three to whichever dns_records existed at the time.
        sa.Column("propagation_status", sa.String(32), nullable=True),
        sa.Column("propagation_checked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("propagation_detail", sa.Text, nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
        ),
    )
    op.create_index("ix_dns_records_zone_id", "dns_records", ["zone_id"])
    op.create_index("ix_dns_records_provider_id", "dns_records", ["provider_id"])
    op.create_index("ix_dns_records_linked_object_id", "dns_records", ["linked_object_id"])
    op.create_index("ix_dns_records_zone_type", "dns_records", ["zone_id", "record_type"])
    op.create_index(
        "ix_dns_records_linked", "dns_records", ["linked_object_type", "linked_object_id"]
    )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names())

    if _LEGACY_NAME not in tables:
        return

    op.drop_table("dns_records")
    op.rename_table(_LEGACY_NAME, "dns_records")
    op.execute("ALTER INDEX IF EXISTS ix_dns_records_legacy_project_id RENAME TO ix_dns_records_project_id")
