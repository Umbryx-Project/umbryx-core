"""add node_status to attack_steps"""

from alembic import op
import sqlalchemy as sa

revision = "048"
down_revision = "047"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("attack_steps", sa.Column("node_status", sa.String(), nullable=True, server_default="hypothetical"))


def downgrade() -> None:
    op.drop_column("attack_steps", "node_status")
