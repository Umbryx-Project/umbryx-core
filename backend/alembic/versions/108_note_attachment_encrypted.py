"""note_attachments.file_encrypted (confidential attachments at rest)

Revision ID: 108
Revises: 107
Create Date: 2026-10-29

External review 2026-10-29 (LOW): confidential notes encrypted their
text body but attachments landed in storage as plaintext blobs — the
same protection loot files already had. New uploads set the flag and
store ciphertext; the download path decrypts on the fly.
"""

from alembic import op
import sqlalchemy as sa

revision = "108"
down_revision = "107"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "note_attachments",
        sa.Column(
            "file_encrypted",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )


def downgrade() -> None:
    op.drop_column("note_attachments", "file_encrypted")
