"""
Phase 2.6 — Tests for per-project DEK, key rotation, encryption API.

2026-08-30: Cred.secret / ProjectSecret.value_enc were made to actually go
through the per-project DEK (encrypt_for_project/decrypt_for_project)
instead of the global KEK they silently used before — see
core/key_management.py and routers/encryption.py::rotate_project_dek.
That means the "rotate-dek always fails" tests below no longer describe
real behavior and have been replaced with tests that rotation actually
works, plus a narrower negative test for the still-real F12 property
(don't fake success on a value that can't be decrypted).
"""
import pytest
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
USER_PASS = "KeyPass1234!"

_s: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient, module_db):
    c = module_client
    c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = c.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200

    r = c.post("/api/admin/users", json={"username": "dek_platadmin", "password": USER_PASS, "role": "platform_admin"})
    assert r.status_code in (200, 201)
    _s["platadmin_uid"] = r.json()["id"]

    r = c.post("/api/projects", json={"name": "DEK Test", "added": "2025-01-01T00:00:00Z", "status": "active"})
    _s["pid"] = r.json()["id"]

    r = c.post("/api/creds", json={"pid": _s["pid"], "username": "dektest", "secret": "secret-dek-test", "type": "plain"})
    assert r.status_code == 201
    _s["cred_id"] = r.json()["id"]
    yield
    c.post("/api/auth/logout")


def _as(c: TestClient, username: str):
    c.post("/api/auth/logout")
    r = c.post("/api/auth/login", json={"username": username, "password": USER_PASS})
    assert r.status_code == 200


def _as_admin(c: TestClient):
    c.post("/api/auth/logout")
    r = c.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200


class TestEncryptDecrypt:
    def test_encrypt_decrypt_roundtrip(self, module_db):
        from app.core.key_management import encrypt_for_project, decrypt_for_project
        plaintext = "my-super-secret-value"
        encrypted = encrypt_for_project(module_db, _s["pid"], plaintext)
        assert encrypted.startswith("__pdek__:")
        assert encrypted != plaintext
        decrypted = decrypt_for_project(module_db, _s["pid"], encrypted)
        assert decrypted == plaintext

    def test_empty_string_passthrough(self, module_db):
        from app.core.key_management import encrypt_for_project, decrypt_for_project
        assert encrypt_for_project(module_db, _s["pid"], "") == ""
        assert decrypt_for_project(module_db, _s["pid"], "") == ""

    def test_legacy_global_kek_value_still_decrypts(self, module_db):
        # Values written before this project had its own DEK (or not yet
        # touched by the data migration) carry the global-KEK sentinel —
        # decrypt_for_project must still read them correctly.
        from app.core.crypto import encrypt_str
        from app.core.key_management import decrypt_for_project
        legacy = encrypt_str("legacy-plaintext")
        assert legacy.startswith("__enc__:")
        assert decrypt_for_project(module_db, _s["pid"], legacy) == "legacy-plaintext"

    def test_same_dek_returned(self, module_db):
        from app.core.key_management import get_or_create_dek
        dek1 = get_or_create_dek(module_db, _s["pid"])
        dek2 = get_or_create_dek(module_db, _s["pid"])
        assert dek1 == dek2

    def test_dek_persisted(self, module_db):
        from app import models
        row = module_db.query(models.ProjectEncryptionKey).filter(models.ProjectEncryptionKey.project_id == _s["pid"]).first()
        assert row is not None
        assert row.version == 1

    def test_different_projects_different_keys(self, module_db, module_client: TestClient):
        from app.core.key_management import encrypt_for_project, decrypt_for_project
        r = module_client.post("/api/projects", json={"name": "DEK Test 2", "added": "2025-01-01T00:00:00Z", "status": "active"})
        pid2 = r.json()["id"]
        enc1 = encrypt_for_project(module_db, _s["pid"], "test-value")
        enc2 = encrypt_for_project(module_db, pid2, "test-value")
        assert enc1 != enc2
        assert decrypt_for_project(module_db, _s["pid"], enc1) == "test-value"
        assert decrypt_for_project(module_db, pid2, enc2) == "test-value"


class TestDEKRotationAPI:
    def test_rotate_dek_succeeds_and_reencrypts(self, module_client: TestClient, module_db):
        from app import models

        cred_before = module_db.query(models.Cred).filter(models.Cred.id == _s["cred_id"]).first()
        assert cred_before.secret.startswith("__pdek__:")
        ciphertext_before = cred_before.secret

        r = module_client.post("/api/system/encryption/rotate-dek", json={"project_id": _s["pid"]})
        assert r.status_code == 200, r.text
        assert r.json()["version"] == 2

        module_db.expire_all()
        cred_after = module_db.query(models.Cred).filter(models.Cred.id == _s["cred_id"]).first()
        assert cred_after.secret.startswith("__pdek__:")
        assert cred_after.secret != ciphertext_before  # actually re-encrypted, not a no-op

        r = module_client.get(f"/api/creds/{_s['cred_id']}/secret")
        assert r.status_code == 200
        assert r.json()["secret"] == "secret-dek-test"

        # Rotating again must also succeed (proves this isn't a one-shot fluke).
        r = module_client.post("/api/system/encryption/rotate-dek", json={"project_id": _s["pid"]})
        assert r.status_code == 200, r.text
        assert r.json()["version"] == 3
        _s["version_before_corrupt_rotation"] = 3

    def test_rotate_dek_fails_loudly_on_undecryptable_pdek_value(self, module_client: TestClient, module_db):
        # Security audit finding F12: a value that claims to be protected by
        # this project's current DEK (the sentinel says so) but can't
        # actually be decrypted with it must abort the whole rotation
        # loudly, not silently skip it and report success.
        from app import models
        from app.core.key_management import PDEK_SENTINEL
        from app.core.utils import new_id

        bad_cred = models.Cred(
            id=new_id("crd"),
            pid=_s["pid"],
            username="corrupted",
            secret=f"{PDEK_SENTINEL}not-a-valid-fernet-token",
            type="plain",
        )
        module_db.add(bad_cred)
        module_db.commit()

        r = module_client.post("/api/system/encryption/rotate-dek", json={"project_id": _s["pid"]})
        assert r.status_code == 500, r.text
        assert "could not be decrypted" in r.text

        module_db.delete(module_db.query(models.Cred).filter(models.Cred.id == bad_cred.id).first())
        module_db.commit()

    def test_cred_still_decryptable_after_failed_rotation(self, module_client: TestClient):
        r = module_client.get(f"/api/creds/{_s['cred_id']}/secret")
        assert r.status_code == 200
        assert r.json()["secret"] == "secret-dek-test"

    def test_list_keys_version_unchanged_after_failed_rotation(self, module_client: TestClient):
        r = module_client.get("/api/system/encryption/keys")
        assert r.status_code == 200
        keys = r.json()
        assert any(
            k["project_id"] == _s["pid"] and k["version"] == _s["version_before_corrupt_rotation"]
            for k in keys
        )

    def test_platadmin_can_list_keys(self, module_client: TestClient):
        _as(module_client, "dek_platadmin")
        r = module_client.get("/api/system/encryption/keys")
        assert r.status_code == 200
        _as_admin(module_client)

    def test_operator_blocked_from_rotate(self, module_client: TestClient):
        r = module_client.post("/api/admin/users", json={"username": "dek_operator", "password": USER_PASS, "role": "user"})
        uid = r.json()["id"]
        module_client.post(f"/api/projects/{_s['pid']}/members", json={"user_id": uid, "role": "operator"})
        _as(module_client, "dek_operator")
        r = module_client.post("/api/system/encryption/rotate-dek", json={"project_id": _s["pid"]})
        assert r.status_code == 403
        _as_admin(module_client)
