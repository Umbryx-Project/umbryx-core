"""
ФТ-4 (fingerprint) / ФТ-5 (signed license token verification) per
docs/modules/LICENSING_TZ.md.

Licensing is per self-hosted instance, not per Organization — see
core/license.py's module docstring. Tests sign their own throwaway
Ed25519 keypair and monkeypatch app.core.license.PUBLIC_KEY_B64 to match
it — the real production public key is a fixed source constant, so tests
can't verify against real tokens without either committing the real
private key (never) or substituting a test keypair (what this file does).
"""
import base64
import json
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app.core import license as license_module

from ._license_test_utils import reset_instance_license

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
USER_PASS = "RolePass1234!"
_s: dict = {}

_TEST_PRIVATE_KEY = Ed25519PrivateKey.generate()
_OTHER_PRIVATE_KEY = Ed25519PrivateKey.generate()  # simulates a forged/wrong key


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _sign(claims: dict, private_key: Ed25519PrivateKey) -> str:
    payload = json.dumps(claims).encode()
    sig = private_key.sign(payload)
    return f"{_b64e(payload)}.{_b64e(sig)}"


@pytest.fixture(autouse=True)
def _patch_public_key(monkeypatch):
    pub_bytes = _TEST_PRIVATE_KEY.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    monkeypatch.setattr(license_module, "PUBLIC_KEY_B64", _b64e(pub_bytes))


def _create_user(c: TestClient, username: str) -> str:
    r = c.post("/api/admin/users", json={"username": username, "password": USER_PASS, "role": "user"})
    assert r.status_code in (200, 201), f"create user {username}: {r.text}"
    return r.json()["id"]


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient, module_db):
    reset_instance_license(module_db)
    c = module_client
    c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = c.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200

    _s["outsider"] = _create_user(c, "license_outsider")

    yield
    c.post("/api/auth/logout")
    reset_instance_license(module_db)


def _valid_claims(fingerprint: str, **overrides) -> dict:
    claims = {
        "tier": "pro",
        "features": ["infra_lifecycle", "workstations", "dns_management"],
        "max_members": -1,
        "max_infra_instances": -1,
        "max_workstations": -1,
        "fingerprint": fingerprint,
        "issued_at": time.time(),
        "expires_at": time.time() + 3600,
    }
    claims.update(overrides)
    return claims


class TestFingerprint:
    def test_fingerprint_is_stable_across_calls(self, module_client: TestClient):
        c = module_client
        r1 = c.get("/api/system/license/fingerprint")
        assert r1.status_code == 200, r1.text
        r2 = c.get("/api/system/license/fingerprint")
        assert r2.status_code == 200
        assert r1.json()["fingerprint"] == r2.json()["fingerprint"]
        assert len(r1.json()["fingerprint"]) == 64  # sha256 hex digest

    def test_fingerprint_requires_platform_admin(self, module_client: TestClient):
        c = module_client
        c.post("/api/auth/logout")
        c.post("/api/auth/login", json={"username": "license_outsider", "password": USER_PASS})
        r = c.get("/api/system/license/fingerprint")
        assert r.status_code == 403
        c.post("/api/auth/logout")
        c.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})


class TestHardwareId:
    """get_hardware_id() specifically targets surviving a disk-level VM
    clone (see core/license.py's module docstring) — install_uuid alone
    doesn't, since a raw disk/DB copy duplicates it 1:1."""

    def test_falls_back_to_empty_when_nothing_reachable(self, monkeypatch):
        # Every source patched to "unreachable/empty" — the test used to
        # rely on the sandbox having no metadata service and no readable
        # DMI table, which is true on some CI runners and false on others
        # (GitHub-hosted runners DO expose /sys/class/dmi/id). Deterministic
        # here: patch the whole chain and assert the empty fallback plus
        # the never-raises contract.
        for name in (
            "_aws_instance_id",
            "_gcp_instance_id",
            "_azure_vm_id",
            "_hetzner_instance_id",
            "_digitalocean_droplet_id",
            "_dmi_system_uuid",
        ):
            monkeypatch.setattr(license_module, name, lambda: "")
        assert license_module.get_hardware_id() == ""

    def test_uses_first_successful_source_in_order(self, monkeypatch):
        monkeypatch.setattr(license_module, "_aws_instance_id", lambda: "")
        monkeypatch.setattr(license_module, "_gcp_instance_id", lambda: "gcp-abc123")
        monkeypatch.setattr(license_module, "_azure_vm_id", lambda: "should-not-be-reached")
        assert license_module.get_hardware_id() == "gcp-abc123"

    def test_a_raising_source_is_skipped_not_fatal(self, monkeypatch):
        def _boom():
            raise OSError("no route to host")

        monkeypatch.setattr(license_module, "_aws_instance_id", _boom)
        monkeypatch.setattr(license_module, "_gcp_instance_id", _boom)
        monkeypatch.setattr(license_module, "_azure_vm_id", _boom)
        monkeypatch.setattr(license_module, "_hetzner_instance_id", _boom)
        monkeypatch.setattr(license_module, "_digitalocean_droplet_id", _boom)
        monkeypatch.setattr(license_module, "_dmi_system_uuid", lambda: "dmi-uuid-xyz")
        assert license_module.get_hardware_id() == "dmi-uuid-xyz"

    def test_fingerprint_changes_with_hardware_id(self):
        fp_a = license_module.compute_fingerprint("same-install-uuid", "host-a")
        fp_b = license_module.compute_fingerprint("same-install-uuid", "host-b")
        fp_bare = license_module.compute_fingerprint("same-install-uuid", "")
        assert fp_a != fp_b != fp_bare

    def test_get_fingerprint_incorporates_live_hardware_id(self, module_client, module_db, monkeypatch):
        # A disk-level VM clone duplicates install_uuid (it's a DB row)
        # but, per the module docstring, must NOT duplicate a fresh
        # hypervisor/cloud-assigned hardware_id — simulated here by
        # having the "clone" observe a different hardware_id at fingerprint
        # time while install_uuid (already persisted) stays identical.
        monkeypatch.setattr(license_module, "get_hardware_id", lambda: "original-vm")
        fp_original = license_module.get_fingerprint(module_db)

        monkeypatch.setattr(license_module, "get_hardware_id", lambda: "cloned-vm")
        fp_clone = license_module.get_fingerprint(module_db)

        assert fp_original != fp_clone


class TestStatusBeforeAnyLicense:
    def test_status_is_manual_free_before_first_upload(self, module_client: TestClient):
        # Must run before TestLicenseUpload activates anything — pytest
        # runs test classes in file order within a module.
        r = module_client.get("/api/system/license/status")
        assert r.status_code == 200
        data = r.json()
        assert data["source"] == "manual"
        assert data["tier"] == "free"
        assert data["verified_at"] is None


class TestLicenseUpload:
    def test_valid_token_activates_plan(self, module_client: TestClient):
        c = module_client
        fp = c.get("/api/system/license/fingerprint").json()["fingerprint"]
        token = _sign(_valid_claims(fp), _TEST_PRIVATE_KEY)
        r = c.post("/api/system/license/upload", json={"token": token})
        assert r.status_code == 201, r.text
        assert r.json()["tier"] == "pro"

    def test_new_org_created_after_activation_inherits_instance_tier(self, module_client: TestClient):
        # The instance is already licensed "pro" from the previous test —
        # a brand-new org must NOT start at Free (licensing is per
        # instance, every org on it shares the license).
        r = module_client.post("/api/orgs", json={"name": "Post-License Org", "slug": "post-license-org"})
        org_id = r.json()["id"]
        r = module_client.get(f"/api/marketplace/plans/{org_id}")
        assert r.json()["tier"] == "pro"

    def test_wrong_signature_rejected(self, module_client: TestClient):
        c = module_client
        fp = c.get("/api/system/license/fingerprint").json()["fingerprint"]
        token = _sign(_valid_claims(fp), _OTHER_PRIVATE_KEY)
        r = c.post("/api/system/license/upload", json={"token": token})
        assert r.status_code == 402
        assert "signature" in r.json()["detail"].lower()

    def test_expired_token_rejected(self, module_client: TestClient):
        c = module_client
        fp = c.get("/api/system/license/fingerprint").json()["fingerprint"]
        token = _sign(_valid_claims(fp, expires_at=time.time() - 10), _TEST_PRIVATE_KEY)
        r = c.post("/api/system/license/upload", json={"token": token})
        assert r.status_code == 402
        assert "expired" in r.json()["detail"].lower()

    def test_wrong_fingerprint_rejected(self, module_client: TestClient):
        c = module_client
        token = _sign(_valid_claims("0" * 64), _TEST_PRIVATE_KEY)
        r = c.post("/api/system/license/upload", json={"token": token})
        assert r.status_code == 402
        assert "fingerprint" in r.json()["detail"].lower()

    def test_malformed_token_rejected(self, module_client: TestClient):
        r = module_client.post("/api/system/license/upload", json={"token": "not-a-real-token"})
        assert r.status_code == 402

    def test_upload_requires_platform_admin(self, module_client: TestClient):
        c = module_client
        c.post("/api/auth/logout")
        c.post("/api/auth/login", json={"username": "license_outsider", "password": USER_PASS})
        r = c.post("/api/system/license/upload", json={"token": "irrelevant"})
        assert r.status_code == 403
        c.post("/api/auth/logout")
        c.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})


class TestLicenseStatus:
    def test_status_reflects_last_upload(self, module_client: TestClient):
        r = module_client.get("/api/system/license/status")
        assert r.status_code == 200
        data = r.json()
        assert data["source"] == "license_token"
        assert data["tier"] == "pro"
        assert data["verified_at"] is not None
