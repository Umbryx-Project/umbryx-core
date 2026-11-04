"""image_delivery + ssh_host columns"""

revision = "053"
down_revision = "052"
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column("instance_templates", sa.Column("image_delivery", sa.String(), nullable=False, server_default="registry"))
    op.add_column("instance_templates", sa.Column("ssh_host", sa.String(), nullable=True))


def downgrade():
    op.drop_column("instance_templates", "ssh_host")
    op.drop_column("instance_templates", "image_delivery")
