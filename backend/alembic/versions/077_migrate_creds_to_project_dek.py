"""Data migration: re-encrypt Cred.secret / ProjectSecret.value_enc under
each row's per-project DEK instead of the platform's global KEK.

⚠ DATA — irreversibly transforms existing ciphertext (downgrade is a no-op,
see below).

Security audit (2026-08-29, P1-7): these two columns were always encrypted
via core.crypto.encrypt_str (the global KEK), sharing the exact same
"__enc__:" sentinel that core.key_management's per-project DEK hierarchy
also used — which made rotate_project_dek unable to tell which key
protected a given value, so it always failed for any project with real
secrets. As of this release, writes go through
core.key_management.encrypt_for_project (sentinel "__pdek__:"). This
migration brings *existing* rows in line so rotate-dek actually protects
them too, instead of only newly-created secrets.

Best-effort per row: a value that fails to decrypt with the global KEK
(corrupt row, or already something else entirely) is logged and left
untouched rather than aborting the whole migration — matches the
"don't lose data, don't silently claim success" spirit of the
rotate_project_dek F12 fix. Idempotent: only rows still on the legacy
"__enc__:" sentinel are touched; already-migrated ("__pdek__:") or empty
values are skipped, so running this twice is a no-op the second time.

Revision ID: 077
Revises: 076
"""

import logging

from alembic import op

revision = "077"
down_revision = "076"
branch_labels = None
depends_on = None

logger = logging.getLogger("alembic.runtime.migration")

_LEGACY_SENTINEL = "__enc__:"


def _migrate_column(session, model, column_name: str, pid_field: str = "pid") -> tuple[int, int]:
    from app.core.crypto import decrypt_str
    from app.core.key_management import encrypt_for_project

    migrated = 0
    skipped = 0
    rows = (
        session.query(model).filter(getattr(model, column_name).like(f"{_LEGACY_SENTINEL}%")).all()
    )
    for row in rows:
        value = getattr(row, column_name)
        pid = getattr(row, pid_field)
        try:
            plaintext = decrypt_str(value)
        except Exception as exc:
            logger.warning(
                "077_migrate_creds_to_project_dek: could not decrypt %s.%s=%r for pid=%s "
                "with the global KEK — leaving it untouched: %s",
                model.__name__,
                column_name,
                row.id,
                pid,
                exc,
            )
            skipped += 1
            continue
        setattr(row, column_name, encrypt_for_project(session, pid, plaintext))
        migrated += 1
    return migrated, skipped


def upgrade() -> None:
    from sqlalchemy.orm import Session

    from app import models

    conn = op.get_bind()
    session = Session(bind=conn)
    try:
        cred_migrated, cred_skipped = _migrate_column(session, models.Cred, "secret")
        secret_migrated, secret_skipped = _migrate_column(
            session, models.ProjectSecret, "value_enc", pid_field="project_id"
        )
        session.commit()
        logger.info(
            "077_migrate_creds_to_project_dek: Cred.secret migrated=%d skipped=%d, "
            "ProjectSecret.value_enc migrated=%d skipped=%d",
            cred_migrated,
            cred_skipped,
            secret_migrated,
            secret_skipped,
        )
    finally:
        session.close()


def downgrade() -> None:
    # Not reversible: re-encrypting back under the global KEK would defeat
    # the whole point (per-project rotation) and there's no way to tell,
    # post-migration, which rows this migration actually touched versus
    # ones a rotate-dek call has since re-encrypted again. Data encrypted
    # under a per-project DEK remains readable regardless (decrypt_for_
    # project handles both sentinels), so there is nothing broken to roll
    # back — this is intentionally a no-op.
    logger.warning(
        "077_migrate_creds_to_project_dek: downgrade is a no-op by design "
        "(see migration docstring) — per-project-DEK-encrypted values are "
        "left as-is and remain readable."
    )
