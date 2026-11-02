"""Notes: optional link to a single host

Decision (see docs/modules/HANDS_ON.md entry for this feature): a note may be
attached to at most ONE host, not many — matches the existing HostActivity /
Cred host-attachment pattern in this codebase, and matches the product
requirement (a note "belongs to" a host for the host-card view + reverse
navigation link, not a many-to-many tagging relationship). Nullable, so
existing notes and project-level (unattached) notes are unaffected.

Revision ID: 074
Revises: 073
"""
from alembic import op
import sqlalchemy as sa

revision = "074"
down_revision = "073"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("notes", sa.Column("host_id", sa.String, nullable=True))
    op.create_foreign_key(
        "fk_notes_host_id", "notes", "hosts", ["host_id"], ["id"], ondelete="SET NULL"
    )
    op.create_index("ix_notes_host_id", "notes", ["host_id"])


def downgrade() -> None:
    op.drop_index("ix_notes_host_id", table_name="notes")
    op.drop_constraint("fk_notes_host_id", "notes", type_="foreignkey")
    op.drop_column("notes", "host_id")
