"""WS provider column + cloud provider support."""

from alembic import op
import sqlalchemy as sa

revision = "033"
down_revision = "032"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "operator_workstations",
        sa.Column("provider", sa.String(), nullable=False, server_default="docker"),
    )


def downgrade() -> None:
    op.drop_column("operator_workstations", "provider")
