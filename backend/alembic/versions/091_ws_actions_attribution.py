"""workstation_actions: ssh_client + tty for session attribution

Revision ID: 091
Revises: 090
"""

import sqlalchemy as sa
from alembic import op

revision = "091"
down_revision = "090"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "workstation_actions",
        sa.Column("ssh_client", sa.String(), nullable=False, server_default=""),
    )
    op.add_column(
        "workstation_actions",
        sa.Column("tty", sa.String(), nullable=False, server_default=""),
    )


def downgrade() -> None:
    op.drop_column("workstation_actions", "tty")
    op.drop_column("workstation_actions", "ssh_client")
