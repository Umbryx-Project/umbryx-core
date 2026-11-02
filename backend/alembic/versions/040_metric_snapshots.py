"""Metric snapshots table + performance indexes.

Revision ID: 040
Revises: 039
"""
from alembic import op
import sqlalchemy as sa

revision = "040"
down_revision = "039"


def upgrade():
    op.create_table(
        "metric_snapshots",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("pid", sa.String, nullable=True),
        sa.Column("scope", sa.String, nullable=False, server_default="local"),
        sa.Column("metric_key", sa.String, nullable=False),
        sa.Column("value", sa.String, nullable=False, server_default="0"),
        sa.Column("dims", sa.Text, nullable=False, server_default="{}"),
        sa.Column("captured_at", sa.String, nullable=False),
    )
    op.create_index("ix_ms_key_captured", "metric_snapshots", ["metric_key", "captured_at"])
    op.create_index("ix_ms_pid_key", "metric_snapshots", ["pid", "metric_key"])

    op.create_index("ix_apn_path_id", "attack_path_nodes", ["path_id"])
    op.create_index("ix_apn_pid", "attack_path_nodes", ["pid"])
    op.create_index("ix_ape_path_id", "attack_path_edges", ["path_id"])
    op.create_index("ix_ape_from_node", "attack_path_edges", ["from_node"])
    op.create_index("ix_ape_to_node", "attack_path_edges", ["to_node"])
    op.create_index("ix_ape_branch_id", "attack_path_edges", ["branch_id"])
    op.create_index("ix_apb_path_id", "attack_path_branches", ["path_id"])
    op.create_index("ix_el_src", "entity_links", ["src_type", "src_id"])
    op.create_index("ix_el_dst", "entity_links", ["dst_type", "dst_id"])
    op.create_index("ix_el_link_type", "entity_links", ["link_type"])
    op.create_index("ix_el_pid", "entity_links", ["pid"])


def downgrade():
    op.drop_index("ix_el_pid", "entity_links")
    op.drop_index("ix_el_link_type", "entity_links")
    op.drop_index("ix_el_dst", "entity_links")
    op.drop_index("ix_el_src", "entity_links")
    op.drop_index("ix_apb_path_id", "attack_path_branches")
    op.drop_index("ix_ape_branch_id", "attack_path_edges")
    op.drop_index("ix_ape_to_node", "attack_path_edges")
    op.drop_index("ix_ape_from_node", "attack_path_edges")
    op.drop_index("ix_ape_path_id", "attack_path_edges")
    op.drop_index("ix_apn_pid", "attack_path_nodes")
    op.drop_index("ix_apn_path_id", "attack_path_nodes")
    op.drop_index("ix_ms_pid_key", "metric_snapshots")
    op.drop_index("ix_ms_key_captured", "metric_snapshots")
    op.drop_table("metric_snapshots")
