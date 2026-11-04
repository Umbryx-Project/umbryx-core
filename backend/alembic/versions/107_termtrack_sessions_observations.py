"""workstation sessions + observations (termtrack P0-P2)

Revision ID: 107
Revises: 106
Create Date: 2026-10-13

Worker Activity Tracking / Deconfliction / auto-enrichment (track D):

- workstation_sessions: one row per correlated login shell (hook events
  + PTY recording share the tty), carrying the nested-SSH path with
  explicit confirmation flags;
- observations: structured facts extracted from terminal output with
  provenance back to the command/session and a unique dedup hash so
  re-harvest never duplicates;
- workstation_actions.session_id links existing rows into sessions;
- host_claims.generalized: claim_type host|range|task, host_id becomes
  nullable, claim_target carries the range/CIDR or free-text task.
  Existing rows are host claims — backfilled explicitly.
"""

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "107"
down_revision = "106"


def upgrade() -> None:
    op.create_table(
        "workstation_sessions",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("workstation_id", sa.String(), nullable=False),
        sa.Column("pid", sa.String(), nullable=True),
        sa.Column("tty", sa.String(), nullable=False, server_default=""),
        sa.Column("username", sa.String(), nullable=False, server_default=""),
        sa.Column("user_id", sa.String(), nullable=True),
        sa.Column("ssh_client", sa.String(), nullable=False, server_default=""),
        sa.Column("state", sa.String(), nullable=False, server_default="active"),
        sa.Column("started_at", sa.String(), nullable=False),
        sa.Column("last_event_at", sa.String(), nullable=False),
        sa.Column("ended_at", sa.String(), nullable=True),
        sa.Column("path", JSONB(), nullable=False),
        sa.Column("pty_log", sa.Text(), nullable=False, server_default=""),
        sa.Column("pty_bytes", sa.String(), nullable=False, server_default="0"),
        sa.Column("last_source", sa.String(), nullable=False, server_default=""),
        sa.Column("note", sa.Text(), nullable=False, server_default=""),
        sa.ForeignKeyConstraint(["workstation_id"], ["operator_workstations.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_ws_sessions_ws_tty", "workstation_sessions", ["workstation_id", "tty"])
    op.create_index("ix_ws_sessions_pid_state", "workstation_sessions", ["pid", "state"])

    op.create_table(
        "observations",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("pid", sa.String(), nullable=False),
        sa.Column("workstation_id", sa.String(), nullable=False),
        sa.Column("session_id", sa.String(), nullable=True),
        sa.Column("action_id", sa.String(), nullable=True),
        sa.Column("tool", sa.String(), nullable=False, server_default=""),
        sa.Column("kind", sa.String(), nullable=False),
        sa.Column("data", JSONB(), nullable=False),
        sa.Column("confidence", sa.String(), nullable=False, server_default="direct"),
        sa.Column("status", sa.String(), nullable=False, server_default="pending"),
        sa.Column("dedup_hash", sa.String(), nullable=False),
        sa.Column("observed_at", sa.String(), nullable=False),
        sa.Column("applied_at", sa.String(), nullable=True),
        sa.Column("provenance", JSONB(), nullable=False),
        sa.Column("target_host_id", sa.String(), nullable=True),
        sa.Column("summary", sa.Text(), nullable=False, server_default=""),
        sa.ForeignKeyConstraint(["workstation_id"], ["operator_workstations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["session_id"], ["workstation_sessions.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["action_id"], ["workstation_actions.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["target_host_id"], ["hosts.id"], ondelete="SET NULL"),
    )
    op.create_index("uq_observations_dedup", "observations", ["dedup_hash"], unique=True)
    op.create_index("ix_observations_pid_status", "observations", ["pid", "status"])

    op.add_column(
        "workstation_actions",
        sa.Column("session_id", sa.String(), nullable=True),
    )
    op.create_index("ix_ws_actions_session", "workstation_actions", ["session_id"])

    op.add_column("host_claims", sa.Column("claim_type", sa.String(), nullable=False, server_default="host"))
    op.add_column("host_claims", sa.Column("claim_target", sa.String(), nullable=False, server_default=""))
    op.alter_column("host_claims", "host_id", existing_type=sa.String(), nullable=True)
    # every pre-107 row is a host claim — make the backfill explicit
    op.execute("UPDATE host_claims SET claim_type = 'host' WHERE claim_type IS NULL OR claim_type = ''")


def downgrade() -> None:
    op.execute("DELETE FROM host_claims WHERE claim_type IN ('range', 'task')")
    op.alter_column("host_claims", "host_id", existing_type=sa.String(), nullable=False)
    op.drop_column("host_claims", "claim_target")
    op.drop_column("host_claims", "claim_type")
    op.drop_index("ix_ws_actions_session", table_name="workstation_actions")
    op.drop_column("workstation_actions", "session_id")
    op.drop_index("ix_observations_pid_status", table_name="observations")
    op.drop_index("uq_observations_dedup", table_name="observations")
    op.drop_table("observations")
    op.drop_index("ix_ws_sessions_pid_state", table_name="workstation_sessions")
    op.drop_index("ix_ws_sessions_ws_tty", table_name="workstation_sessions")
    op.drop_table("workstation_sessions")
