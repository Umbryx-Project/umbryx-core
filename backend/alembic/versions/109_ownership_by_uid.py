"""ownership by user id: custom_playbooks/operation_packs.created_by_uid

Revision ID: 109
Revises: 108
Create Date: 2026-10-29

External review 2026-10-29 (LOW): ownership of custom playbooks and
operation packs was keyed by USERNAME — renaming a user or re-creating
an account silently orphaned their packs. Adds created_by_uid, stores
user.id going forward, backfills from the username for existing rows.
Rows whose author cannot be resolved keep uid NULL and fall back to the
historical username match in the permission helpers.
"""

from alembic import op
import sqlalchemy as sa

revision = "109"
down_revision = "108"
branch_labels = None
depends_on = None

_TABLES = ("custom_playbooks", "operation_packs")


def upgrade() -> None:
    for t in _TABLES:
        op.add_column(t, sa.Column("created_by_uid", sa.String(), nullable=True))
        op.create_index(f"ix_{t}_created_by_uid", t, ["created_by_uid"])
        # backfill: resolve the display username to a user id where possible
        op.execute(
            f"UPDATE {t} SET created_by_uid = ("
            " SELECT u.id FROM users u"
            f" WHERE u.username = {t}.created_by"
            ") WHERE created_by_uid IS NULL AND created_by <> ''"
        )


def downgrade() -> None:
    for t in _TABLES:
        op.drop_index(f"ix_{t}_created_by_uid", table_name=t)
        op.drop_column(t, "created_by_uid")
