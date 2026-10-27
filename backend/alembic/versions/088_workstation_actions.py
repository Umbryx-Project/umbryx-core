"""workstation_actions: operator command audit log from workstation shells

Revision ID: 088
Revises: 087

A bash DEBUG-trap hook (injected over the platform's management channel)
POSTs every operator command with a per-workstation token. The log backs
two features: the engagement audit trail (what was actually run, by whom,
when) and automatic deconfliction (recent commands parsed for target IPs
— an operator typing nmap/smbclient against a host is the strongest
busy-signal the engagement map can get).
"""

import sqlalchemy as sa
from alembic import op

revision = "088"
down_revision = "087"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "workstation_actions",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column(
            "workstation_id",
            sa.String(),
            sa.ForeignKey("operator_workstations.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("pid", sa.String(), nullable=True),
        sa.Column("username", sa.String(), nullable=False, server_default=""),
        sa.Column("command", sa.Text(), nullable=False, server_default=""),
        sa.Column("cwd", sa.String(), nullable=False, server_default=""),
        sa.Column("source", sa.String(), nullable=False, server_default="shell-hook"),
        sa.Column("ts", sa.String(), nullable=False),
    )
    op.create_index("ix_ws_actions_ws_ts", "workstation_actions", ["workstation_id", "ts"])
    op.create_index("ix_ws_actions_pid_ts", "workstation_actions", ["pid", "ts"])


def downgrade() -> None:
    op.drop_index("ix_ws_actions_pid_ts", table_name="workstation_actions")
    op.drop_index("ix_ws_actions_ws_ts", table_name="workstation_actions")
    op.drop_table("workstation_actions")
