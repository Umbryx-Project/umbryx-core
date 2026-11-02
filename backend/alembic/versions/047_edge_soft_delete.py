"""edge soft delete + attack path fixes"""

from alembic import op
import sqlalchemy as sa

revision = "047"
down_revision = "046"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("attack_path_edges", sa.Column("deleted_at", sa.String, nullable=True))


def downgrade() -> None:
    op.drop_column("attack_path_edges", "deleted_at")
