"""surface_watches: continuous attack-surface monitoring

Revision ID: 085
Revises: 084

A SurfaceWatch runs a periodic light nmap over a project's scope (through
the existing attacker transport and scan pipeline — results land in the
Host graph like any manual scan), then diffs the host/port state against
the stored baseline. Growth of the attack surface (new hosts, new open
ports, status flips) notifies project members in-app and writes a
timeline event — turning the platform from an engagement tool into a
continuous attack-surface monitor between engagements.
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "085"
down_revision = "084"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "surface_watches",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column(
            "pid", sa.String(), sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False
        ),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default="true"),
        sa.Column("interval_minutes", sa.Integer(), nullable=False, server_default="60"),
        sa.Column("targets", sa.String(), nullable=False, server_default=""),
        sa.Column("intensity_profile", sa.String(), nullable=False, server_default="normal"),
        sa.Column("state", sa.String(), nullable=False, server_default="idle"),
        sa.Column("last_run_at", sa.String(), nullable=True),
        sa.Column("last_change_at", sa.String(), nullable=True),
        sa.Column("last_job_id", sa.String(), nullable=False, server_default=""),
        sa.Column("baseline_json", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("last_diff_json", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("created_by", sa.String(), nullable=True),
        sa.Column("created_at", sa.String(), nullable=False),
    )
    op.create_index("ix_surface_watches_pid_enabled", "surface_watches", ["pid", "enabled"])


def downgrade() -> None:
    op.drop_index("ix_surface_watches_pid_enabled", table_name="surface_watches")
    op.drop_table("surface_watches")
