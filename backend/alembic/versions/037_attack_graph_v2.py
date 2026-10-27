"""Attack graph v2: nodes/edges/branches tables, entity_links, attack_paths extensions

Revision ID: 037
Revises: 036
"""
from alembic import op
import sqlalchemy as sa

revision = "037"
down_revision = "036"


def upgrade():
    op.add_column("attack_paths", sa.Column("status", sa.String, nullable=False, server_default="draft"))
    op.add_column("attack_paths", sa.Column("risk_score", sa.Integer, nullable=True))
    op.add_column("attack_paths", sa.Column("impact_score", sa.Integer, nullable=True))
    op.add_column("attack_paths", sa.Column("likelihood_score", sa.Integer, nullable=True))
    op.add_column("attack_paths", sa.Column("version", sa.Integer, nullable=False, server_default="1"))
    op.add_column("attack_paths", sa.Column("created_by", sa.String, nullable=True))
    op.add_column("attack_paths", sa.Column("updated_at", sa.String, nullable=True))
    op.add_column("attack_paths", sa.Column("deleted_at", sa.String, nullable=True))

    op.create_table(
        "attack_path_nodes",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("path_id", sa.String, sa.ForeignKey("attack_paths.id", ondelete="CASCADE"), nullable=False),
        sa.Column("pid", sa.String, nullable=False),
        sa.Column("kind", sa.String, nullable=False, server_default="step"),
        sa.Column("label", sa.String, nullable=False, server_default=""),
        sa.Column("sublabel", sa.String, nullable=False, server_default=""),
        sa.Column("technique", sa.String, nullable=False, server_default=""),
        sa.Column("mitre_id", sa.String, nullable=False, server_default=""),
        sa.Column("notes", sa.Text, nullable=False, server_default=""),
        sa.Column("node_status", sa.String, nullable=False, server_default="hypothetical"),
        sa.Column("confidence", sa.String, nullable=False, server_default="0.5"),
        sa.Column("ref_type", sa.String, nullable=True),
        sa.Column("ref_id", sa.String, nullable=True),
        sa.Column("position", sa.Text, nullable=False, server_default="{}"),
        sa.Column("host_id", sa.String, sa.ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_by", sa.String, nullable=True),
        sa.Column("ts", sa.String, nullable=False),
        sa.Column("deleted_at", sa.String, nullable=True),
    )

    op.create_table(
        "attack_path_branches",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("path_id", sa.String, sa.ForeignKey("attack_paths.id", ondelete="CASCADE"), nullable=False),
        sa.Column("pid", sa.String, nullable=False),
        sa.Column("name", sa.String, nullable=False, server_default=""),
        sa.Column("root_node", sa.String, sa.ForeignKey("attack_path_nodes.id", ondelete="SET NULL"), nullable=True),
        sa.Column("status", sa.String, nullable=False, server_default="hypothetical"),
        sa.Column("owner_user_id", sa.String, nullable=True),
        sa.Column("probability", sa.String, nullable=False, server_default="0.5"),
        sa.Column("complexity", sa.String, nullable=False, server_default="medium"),
        sa.Column("risk_score", sa.Integer, nullable=True),
        sa.Column("parent_branch_id", sa.String, sa.ForeignKey("attack_path_branches.id", ondelete="SET NULL"), nullable=True),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("created_by", sa.String, nullable=True),
        sa.Column("ts", sa.String, nullable=False),
        sa.Column("deleted_at", sa.String, nullable=True),
    )

    op.create_table(
        "attack_path_edges",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("path_id", sa.String, sa.ForeignKey("attack_paths.id", ondelete="CASCADE"), nullable=False),
        sa.Column("pid", sa.String, nullable=False),
        sa.Column("from_node", sa.String, sa.ForeignKey("attack_path_nodes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("to_node", sa.String, sa.ForeignKey("attack_path_nodes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("edge_type", sa.String, nullable=False, server_default="leads_to"),
        sa.Column("branch_id", sa.String, sa.ForeignKey("attack_path_branches.id", ondelete="SET NULL"), nullable=True),
        sa.Column("condition", sa.Text, nullable=False, server_default=""),
        sa.Column("edge_status", sa.String, nullable=False, server_default="hypothetical"),
        sa.Column("weight", sa.Integer, nullable=False, server_default="0"),
        sa.Column("technique", sa.String, nullable=False, server_default=""),
        sa.Column("mitre_id", sa.String, nullable=False, server_default=""),
        sa.Column("created_by", sa.String, nullable=True),
        sa.Column("ts", sa.String, nullable=False),
    )

    op.create_table(
        "entity_links",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("pid", sa.String, nullable=False),
        sa.Column("src_type", sa.String, nullable=False),
        sa.Column("src_id", sa.String, nullable=False),
        sa.Column("dst_type", sa.String, nullable=False),
        sa.Column("dst_id", sa.String, nullable=False),
        sa.Column("link_type", sa.String, nullable=False, server_default="relates_to"),
        sa.Column("comment", sa.Text, nullable=False, server_default=""),
        sa.Column("created_by", sa.String, nullable=True),
        sa.Column("ts", sa.String, nullable=False),
        sa.Column("deleted_at", sa.String, nullable=True),
    )


def downgrade():
    op.drop_table("attack_path_edges")
    op.drop_table("attack_path_branches")
    op.drop_table("attack_path_nodes")
    op.drop_table("entity_links")
    op.drop_column("attack_paths", "deleted_at")
    op.drop_column("attack_paths", "updated_at")
    op.drop_column("attack_paths", "created_by")
    op.drop_column("attack_paths", "version")
    op.drop_column("attack_paths", "likelihood_score")
    op.drop_column("attack_paths", "impact_score")
    op.drop_column("attack_paths", "risk_score")
    op.drop_column("attack_paths", "status")
