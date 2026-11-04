"""Data migration: copy Host.notes free-text into real Notes (Note.host_id)

Host.notes had no `created_at`/`updated_at` column to source a more
meaningful timestamp from, so the migrated note's `ts` is the migration
run time. Migrated notes are tagged "migrated" (Note has no author/creator
column to mark instead) and titled "Migrated host notes" so they're
identifiable in the UI. The old `hosts.notes` column is intentionally left
in place here — see 076_drop_host_notes_column.py, which removes it only
after this data migration has been run and verified (see
docs/modules/HANDS_ON.md entry for this feature: dev-environment migration
created 46 notes from 46 hosts with non-empty `notes`, out of 85 hosts
total — matches exactly, verified before 076 was written).

Revision ID: 075
Revises: 074
"""
import datetime
import secrets

from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import table, column

revision = "075"
down_revision = "074"
branch_labels = None
depends_on = None

_hosts = table(
    "hosts",
    column("id", sa.String),
    column("pid", sa.String),
    column("notes", sa.Text),
)

_notes = table(
    "notes",
    column("id", sa.String),
    column("pid", sa.String),
    column("host_id", sa.String),
    column("title", sa.String),
    column("phase", sa.String),
    column("tags", sa.ARRAY(sa.String)),
    column("content", sa.Text),
    column("ts", sa.String),
    column("starred", sa.Boolean),
    column("version", sa.Integer),
)


def _new_id() -> str:
    return f"n{secrets.token_hex(4)}"


def upgrade() -> None:
    conn = op.get_bind()
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M")
    rows = conn.execute(
        sa.select(_hosts.c.id, _hosts.c.pid, _hosts.c.notes).where(
            sa.and_(_hosts.c.notes.isnot(None), sa.func.trim(_hosts.c.notes) != "")
        )
    ).fetchall()
    for host_id, pid, notes in rows:
        conn.execute(
            _notes.insert().values(
                id=_new_id(),
                pid=pid,
                host_id=host_id,
                title="Migrated host notes",
                phase="recon",
                tags=["migrated"],
                content=notes,
                ts=now,
                starred=False,
                version=0,
            )
        )


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(_notes.delete().where(_notes.c.tags.contains(["migrated"])))
