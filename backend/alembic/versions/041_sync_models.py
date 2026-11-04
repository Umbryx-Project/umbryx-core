"""Sync models: sync_state, conflict_records, sync_events tables + indexes.

Revision ID: 041
Revises: 040
"""
from alembic import op
import sqlalchemy as sa

revision = "041"
down_revision = "040"


def upgrade():
    op.create_table(
        "sync_state",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("instance_id", sa.String, nullable=False),
        sa.Column("entity_type", sa.String, nullable=False),
        sa.Column("entity_id", sa.String, nullable=False),
        sa.Column("local_version", sa.Integer, nullable=False, server_default="0"),
        sa.Column("remote_version", sa.Integer, nullable=False, server_default="0"),
        sa.Column("last_synced_at", sa.String, nullable=True),
        sa.Column("status", sa.String, nullable=False, server_default="in_sync"),
        sa.Column("origin_instance", sa.String, nullable=True),
    )
    op.create_index("ix_ss_instance_entity", "sync_state", ["instance_id", "entity_type", "entity_id"])
    op.create_index("ix_ss_status", "sync_state", ["status"])

    op.create_table(
        "conflict_records",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("entity_type", sa.String, nullable=False),
        sa.Column("entity_id", sa.String, nullable=False),
        sa.Column("local_payload", sa.Text, nullable=False, server_default="{}"),
        sa.Column("remote_payload", sa.Text, nullable=False, server_default="{}"),
        sa.Column("detected_at", sa.String, nullable=False),
        sa.Column("resolution", sa.String, nullable=False, server_default="pending"),
        sa.Column("resolved_by", sa.String, nullable=True),
        sa.Column("resolved_at", sa.String, nullable=True),
    )
    op.create_index("ix_cr_entity", "conflict_records", ["entity_type", "entity_id"])
    op.create_index("ix_cr_resolution", "conflict_records", ["resolution"])

    op.create_table(
        "sync_events",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("seq", sa.Integer, nullable=False),
        sa.Column("instance_id", sa.String, nullable=False),
        sa.Column("entity_type", sa.String, nullable=False),
        sa.Column("entity_id", sa.String, nullable=False),
        sa.Column("op", sa.String, nullable=False),
        sa.Column("payload_hash", sa.String, nullable=True),
        sa.Column("signature", sa.String, nullable=True),
        sa.Column("ts", sa.String, nullable=False),
    )
    op.create_index("ix_se_instance_seq", "sync_events", ["instance_id", "seq"])
    op.create_index("ix_se_entity", "sync_events", ["entity_type", "entity_id"])
    op.create_index("ix_se_ts", "sync_events", ["ts"])


def downgrade():
    op.drop_index("ix_se_ts", "sync_events")
    op.drop_index("ix_se_entity", "sync_events")
    op.drop_index("ix_se_instance_seq", "sync_events")
    op.drop_table("sync_events")

    op.drop_index("ix_cr_resolution", "conflict_records")
    op.drop_index("ix_cr_entity", "conflict_records")
    op.drop_table("conflict_records")

    op.drop_index("ix_ss_status", "sync_state")
    op.drop_index("ix_ss_instance_entity", "sync_state")
    op.drop_table("sync_state")
