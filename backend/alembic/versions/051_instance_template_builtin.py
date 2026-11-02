"""instance_template.is_builtin column"""

revision = "051"
down_revision = "050"
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column("instance_templates", sa.Column("is_builtin", sa.Boolean(), nullable=False, server_default="false"))


def downgrade():
    op.drop_column("instance_templates", "is_builtin")
