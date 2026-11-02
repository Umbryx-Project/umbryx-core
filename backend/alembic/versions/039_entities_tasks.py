"""New entities: tasks, remediations, evidence, identities.

Revision ID: 039
Revises: 038
"""
from alembic import op
import sqlalchemy as sa

revision = "039"
down_revision = "038"


def upgrade():
    op.create_table(
        "tasks",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("pid", sa.String, sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("title", sa.String, nullable=False),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("status", sa.String, nullable=False, server_default="open"),
        sa.Column("assignee", sa.String, nullable=True),
        sa.Column("due_at", sa.String, nullable=True),
        sa.Column("priority", sa.String, nullable=False, server_default="medium"),
        sa.Column("sla_hours", sa.Integer, nullable=True),
        sa.Column("source", sa.String, nullable=True),
        sa.Column("created_by", sa.String, nullable=True),
        sa.Column("ts", sa.String, nullable=False),
        sa.Column("closed_at", sa.String, nullable=True),
        sa.Column("reopened_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("deleted_at", sa.String, nullable=True),
    )
    op.create_table(
        "remediations",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("pid", sa.String, sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding_id", sa.String, sa.ForeignKey("findings.id", ondelete="SET NULL"), nullable=True),
        sa.Column("title", sa.String, nullable=False),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("status", sa.String, nullable=False, server_default="open"),
        sa.Column("owner", sa.String, nullable=True),
        sa.Column("sla_hours", sa.Integer, nullable=True),
        sa.Column("due_at", sa.String, nullable=True),
        sa.Column("verified_by", sa.String, nullable=True),
        sa.Column("verified_at", sa.String, nullable=True),
        sa.Column("created_by", sa.String, nullable=True),
        sa.Column("ts", sa.String, nullable=False),
        sa.Column("deleted_at", sa.String, nullable=True),
    )
    op.create_table(
        "evidence",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("pid", sa.String, sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String, nullable=False, server_default="file"),
        sa.Column("filename", sa.String, nullable=False, server_default=""),
        sa.Column("sha256", sa.String, nullable=True),
        sa.Column("storage_ref", sa.String, nullable=True),
        sa.Column("size_bytes", sa.Integer, nullable=True),
        sa.Column("collected_by", sa.String, nullable=True),
        sa.Column("collected_at", sa.String, nullable=True),
        sa.Column("notes", sa.Text, nullable=False, server_default=""),
        sa.Column("created_by", sa.String, nullable=True),
        sa.Column("ts", sa.String, nullable=False),
    )
    op.create_table(
        "identities",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("pid", sa.String, sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("principal", sa.String, nullable=False),
        sa.Column("domain", sa.String, nullable=False, server_default=""),
        sa.Column("identity_type", sa.String, nullable=False, server_default="user"),
        sa.Column("source", sa.String, nullable=True),
        sa.Column("ref_cred_id", sa.String, nullable=True),
        sa.Column("notes", sa.Text, nullable=False, server_default=""),
        sa.Column("created_by", sa.String, nullable=True),
        sa.Column("ts", sa.String, nullable=False),
        sa.Column("deleted_at", sa.String, nullable=True),
    )


def downgrade():
    op.drop_table("identities")
    op.drop_table("evidence")
    op.drop_table("remediations")
    op.drop_table("tasks")
