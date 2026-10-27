"""instance_template.image_registry column"""

revision = "052"
down_revision = "051"
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column("instance_templates", sa.Column("image_registry", sa.String(), nullable=True))


def downgrade():
    op.drop_column("instance_templates", "image_registry")
