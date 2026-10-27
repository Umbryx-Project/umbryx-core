"""notifications table"""

from alembic import op
import sqlalchemy as sa

revision = "046"
down_revision = "045"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "notifications",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("user_id", sa.String(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("type", sa.String(), nullable=False, server_default="info"),
        sa.Column("title", sa.String(), nullable=False),
        sa.Column("body", sa.Text(), nullable=True),
        sa.Column("link", sa.String(), nullable=True),
        sa.Column("read", sa.Boolean(), nullable=False, server_default="false"),
        sa.Column("read_ts", sa.DateTime(timezone=True), nullable=True),
        sa.Column("project_id", sa.String(), nullable=True),
    )
    op.create_index("ix_notif_user_read", "notifications", ["user_id", "read"])
    op.create_index("ix_notif_user_ts", "notifications", ["user_id", "ts"])


def downgrade() -> None:
    op.drop_index("ix_notif_user_ts")
    op.drop_index("ix_notif_user_read")
    op.drop_table("notifications")
