"""
Tests for alembic/versions/077_migrate_creds_to_project_dek.py.

Exercises the migration's actual logic (_migrate_column) against the test
DB session directly rather than through `alembic upgrade`, since the test
suite's SQLite DB is built via Base.metadata.create_all (see
tests/conftest.py) and shared across the whole test run — so assertions
here check the specific rows each test creates, not the aggregate
migrated/skipped counts (other tests elsewhere in the suite may leave
their own "__enc__:"-prefixed rows behind, which _migrate_column's
unfiltered table scan will also pick up).
"""

import importlib.util
from pathlib import Path

from app import models
from app.core.crypto import encrypt_str
from app.core.key_management import decrypt_for_project, is_project_encrypted
from app.core.utils import new_id, ts_now

_MIGRATION_PATH = (
    Path(__file__).resolve().parent.parent
    / "alembic"
    / "versions"
    / "077_migrate_creds_to_project_dek.py"
)
_spec = importlib.util.spec_from_file_location("_migration_077", _MIGRATION_PATH)
_migration = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_migration)


class TestMigrateColumn:
    def test_migrates_legacy_kek_cred_to_project_dek(self, db):
        pid = new_id("prj")
        db.add(models.Project(id=pid, name="Mig Test", added="2024-01-01"))
        db.commit()
        cred = models.Cred(
            id=new_id("crd"),
            pid=pid,
            username="legacyuser",
            secret=encrypt_str("legacy-secret"),
            type="plain",
        )
        db.add(cred)
        db.commit()
        assert cred.secret.startswith("__enc__:")

        migrated, skipped = _migration._migrate_column(db, models.Cred, "secret")
        db.commit()

        assert migrated >= 1
        db.refresh(cred)
        assert is_project_encrypted(cred.secret)
        assert decrypt_for_project(db, pid, cred.secret) == "legacy-secret"

    def test_idempotent_second_run_is_noop(self, db):
        pid = new_id("prj")
        db.add(models.Project(id=pid, name="Mig Test 2", added="2024-01-01"))
        db.commit()
        cred = models.Cred(
            id=new_id("crd"),
            pid=pid,
            username="u",
            secret=encrypt_str("s"),
            type="plain",
        )
        db.add(cred)
        db.commit()

        _migration._migrate_column(db, models.Cred, "secret")
        db.commit()
        db.refresh(cred)
        assert is_project_encrypted(cred.secret)
        ciphertext_after_first_run = cred.secret

        _migration._migrate_column(db, models.Cred, "secret")
        db.commit()
        db.refresh(cred)

        # Already "__pdek__:"-prefixed — not picked up again, ciphertext
        # (and therefore key/version) unchanged by the second run.
        assert cred.secret == ciphertext_after_first_run
        assert decrypt_for_project(db, pid, cred.secret) == "s"

    def test_skips_and_logs_undecryptable_row(self, db, caplog):
        pid = new_id("prj")
        db.add(models.Project(id=pid, name="Mig Test 3", added="2024-01-01"))
        db.commit()
        bad_cred = models.Cred(
            id=new_id("crd"),
            pid=pid,
            username="corrupted",
            secret="__enc__:not-valid-fernet-ciphertext",
            type="plain",
        )
        db.add(bad_cred)
        db.commit()

        migrated, skipped = _migration._migrate_column(db, models.Cred, "secret")
        db.commit()

        assert skipped >= 1
        db.refresh(bad_cred)
        assert bad_cred.secret == "__enc__:not-valid-fernet-ciphertext"  # untouched

        # Clean up: the test DB session is shared across tests in this
        # module, and _migrate_column scans the whole table unfiltered —
        # leaving this row in place would leak into other tests' counts.
        db.delete(bad_cred)
        db.commit()

    def test_project_secret_value_enc_migrated(self, db):
        pid = new_id("prj")
        db.add(models.Project(id=pid, name="Mig Test 4", added="2024-01-01"))
        db.commit()
        secret = models.ProjectSecret(
            id=new_id("sec"),
            project_id=pid,
            kind="api_token",
            name="test token",
            value_enc=encrypt_str("token-value"),
            issued_at=ts_now(),
        )
        db.add(secret)
        db.commit()

        migrated, skipped = _migration._migrate_column(
            db, models.ProjectSecret, "value_enc", pid_field="project_id"
        )
        db.commit()

        assert migrated >= 1
        db.refresh(secret)
        assert is_project_encrypted(secret.value_enc)
        assert decrypt_for_project(db, pid, secret.value_enc) == "token-value"

    def test_empty_value_not_touched(self, db):
        pid = new_id("prj")
        db.add(models.Project(id=pid, name="Mig Test 5", added="2024-01-01"))
        db.commit()
        cred = models.Cred(id=new_id("crd"), pid=pid, username="nosecret", secret="", type="plain")
        db.add(cred)
        db.commit()

        _migration._migrate_column(db, models.Cred, "secret")
        db.refresh(cred)

        assert cred.secret == ""
