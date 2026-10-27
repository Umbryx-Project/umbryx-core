"""Drop hosts.notes — fully superseded by Note.host_id (see 074, 075)

Run only after 075's data migration has been applied and verified (dev
verification: 46 migrated notes for 46 hosts with non-empty `notes`,
content byte-for-byte identical — see docs/modules/HANDS_ON.md entry for
this feature). All code paths reading/writing Host.notes were ported to
use linked Notes (or removed) before this migration was written.

Revision ID: 076
Revises: 075
"""
from alembic import op
import sqlalchemy as sa

revision = "076"
down_revision = "075"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_column("hosts", "notes")


def downgrade() -> None:
    op.add_column("hosts", sa.Column("notes", sa.Text, nullable=False, server_default=""))
