"""dns_propagation_and_expiration_fields

Revision ID: 064
Revises: 063
"""
from alembic import op
import sqlalchemy as sa

revision = "064"
down_revision = "063"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)

    # ── dns_records: propagation fields ──────────────────────────────
    rec_cols = {c["name"] for c in inspector.get_columns("dns_records")}
    if "propagation_status" not in rec_cols:
        op.add_column("dns_records", sa.Column("propagation_status", sa.String(32), nullable=True))
    if "propagation_checked_at" not in rec_cols:
        op.add_column("dns_records", sa.Column("propagation_checked_at", sa.DateTime(timezone=True), nullable=True))
    if "propagation_detail" not in rec_cols:
        op.add_column("dns_records", sa.Column("propagation_detail", sa.Text, nullable=True))

    # ── dns_zones: expiration fields ─────────────────────────────────
    zone_cols = {c["name"] for c in inspector.get_columns("dns_zones")}
    if "expires_at" not in zone_cols:
        op.add_column("dns_zones", sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True))
    if "expiration_checked_at" not in zone_cols:
        op.add_column("dns_zones", sa.Column("expiration_checked_at", sa.DateTime(timezone=True), nullable=True))
    if "registrar" not in zone_cols:
        op.add_column("dns_zones", sa.Column("registrar", sa.String(256), nullable=True))


def downgrade() -> None:
    for col in ("propagation_detail", "propagation_checked_at", "propagation_status"):
        op.drop_column("dns_records", col)
    for col in ("registrar", "expiration_checked_at", "expires_at"):
        op.drop_column("dns_zones", col)
