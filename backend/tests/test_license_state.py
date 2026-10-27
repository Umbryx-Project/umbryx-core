"""
ФТ-15 (docs/modules/LICENSING_TZ.md): license lifecycle active/grace/wind-down.

Uses the injectable `now` on get_license_status so state transitions are
tested as pure computation, order-independent from the rest of the suite.
"""
import base64
import json
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app.core import license as license_module
from app.core.license_state import get_license_status, notify_admins_if_needed

from ._license_test_utils import reset_instance_license

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
_TEST_PRIVATE_KEY = Ed25519PrivateKey.generate()


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _sign(claims: dict) -> str:
    payload = json.dumps(claims).encode()
    sig = _TEST_PRIVATE_KEY.sign(payload)
    return f"{_b64e(payload)}.{_b64e(sig)}"


@pytest.fixture(autouse=True)
def _patch_public_key(monkeypatch):
    pub_bytes = _TEST_PRIVATE_KEY.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    monkeypatch.setattr(license_module, "PUBLIC_KEY_B64", _b64e(pub_bytes))


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient, module_db):
    reset_instance_license(module_db)
    c = module_client
    c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    c.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    yield
    c.post("/api/auth/logout")
    reset_instance_license(module_db)


@pytest.fixture(autouse=True)
def _clean(module_db):
    reset_instance_license(module_db)
    yield
    reset_instance_license(module_db)


def _apply(module_client, module_db, **overrides):
    from app.core.license import get_fingerprint

    fp = get_fingerprint(module_db)
    claims = {
        "tier": "pro",
        "features": ["infra_lifecycle"],
        "fingerprint": fp,
        "issued_at": time.time(),
        "expires_at": time.time() + 3600,
    }
    claims.update(overrides)
    r = module_client.post("/api/system/license/upload", json={"token": _sign(claims)})
    assert r.status_code == 201, r.text


class TestStates:
    def test_unlicensed_when_no_token(self, module_db):
        assert get_license_status(module_db)["state"] == "unlicensed"

    def test_active_before_expiry(self, module_client, module_db):
        _apply(module_client, module_db, expires_at=time.time() + 3600)
        assert get_license_status(module_db)["state"] == "active"

    def test_grace_just_after_expiry(self, module_client, module_db):
        exp = time.time() + 3600
        _apply(module_client, module_db, expires_at=exp, grace_days=14)
        # 1 day after expiry, within the 14-day grace window.
        status = get_license_status(module_db, now=exp + 86400)
        assert status["state"] == "grace"
        assert status["tier"] == "pro"  # tier retained through grace

    def test_wind_down_after_grace(self, module_client, module_db):
        exp = time.time() + 3600
        _apply(module_client, module_db, expires_at=exp, grace_days=7)
        status = get_license_status(module_db, now=exp + 8 * 86400)
        assert status["state"] == "wind_down"
        # tier reported as free for display, but licensed_tier remembered
        assert status["licensed_tier"] == "pro"

    def test_default_grace_days_when_claim_absent(self, module_client, module_db):
        exp = time.time() + 3600
        _apply(module_client, module_db, expires_at=exp)  # no grace_days
        assert get_license_status(module_db)["grace_days"] == 14

    def test_offline_channel_ignores_heartbeat_staleness(self, module_client, module_db):
        _apply(module_client, module_db, expires_at=time.time() + 10 * 86400)
        module_client.patch("/api/system/license/channel", json={"offline": True})
        # Even with no recent heartbeat, an offline instance stays active
        # until the token's own expiry.
        assert get_license_status(module_db)["state"] == "active"
        module_client.patch("/api/system/license/channel", json={"offline": False})


class TestAdminNotifications:
    def test_grace_notifies_once(self, module_client, module_db):
        exp = time.time() - 86400  # already expired yesterday
        _apply_expired(module_client, module_db, exp)
        first = notify_admins_if_needed(module_db)
        assert first == "grace"
        # second pass in the same stage is deduped
        assert notify_admins_if_needed(module_db) is None


def _apply_expired(module_client, module_db, expires_at):
    """Apply a valid token then age it in place (upload refuses an already
    expired file, by design)."""
    from app.core.license import get_fingerprint

    _apply(module_client, module_db, expires_at=time.time() + 3600, grace_days=14)
    fp = get_fingerprint(module_db)
    aged = _sign(
        {
            "tier": "pro",
            "features": ["infra_lifecycle"],
            "fingerprint": fp,
            "issued_at": time.time() - 100000,
            "expires_at": expires_at,
            "grace_days": 14,
        }
    )
    from app import models

    latest = (
        module_db.query(models.LicenseToken)
        .order_by(models.LicenseToken.verified_at.desc())
        .first()
    )
    latest.raw_token = aged
    module_db.commit()


class TestExpiryReason:
    """The status must distinguish the token's real expiry from the rolling
    heartbeat window, so a healthy online instance doesn't look like it is
    about to expire (the 'expires in ~6 days' false banner)."""

    def _set_heartbeat(self, db, iso):
        from app.core.license import get_instance_license_state
        s = get_instance_license_state(db)
        s.last_heartbeat_ok_at = iso
        db.commit()

    def test_heartbeat_age_never_affects_expiry(self, module_client, module_db):
        # LICENSING_REDESIGN: connectivity no longer shortens the license. A
        # fresh and a long-stale heartbeat both leave the license governed by
        # the token's own expiry.
        import datetime
        now = time.time()
        _apply(module_client, module_db, expires_at=now + 365 * 86400)
        for age_days in (0, 30, 400):  # fresh, stale, very stale
            hb = datetime.datetime.fromtimestamp(now - age_days * 86400, datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            self._set_heartbeat(module_db, hb)
            st = get_license_status(module_db, now=now)
            assert st["state"] == "active"
            assert st["expiry_reason"] == "token"
            assert st["days_left"] == st["token_days_left"] >= 360
            assert st["heartbeat_age_days"] == age_days

    def test_token_near_expiry_reason_is_token(self, module_client, module_db):
        now = time.time()
        _apply(module_client, module_db, expires_at=now + 5 * 86400)
        st = get_license_status(module_db, now=now)
        assert st["expiry_reason"] == "token"
        assert st["token_days_left"] == 5

    def test_revocation_drives_expiry(self, module_client, module_db):
        # A server-confirmed revocation ends the license at that moment, ahead
        # of the token's own (later) expiry.
        import datetime
        now = time.time()
        _apply(module_client, module_db, expires_at=now + 365 * 86400)
        from app.core.license import get_instance_license_state
        s = get_instance_license_state(module_db)
        s.revoked_at = datetime.datetime.fromtimestamp(now - 86400, datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        module_db.commit()
        st = get_license_status(module_db, now=now)
        assert st["expiry_reason"] == "revoked"
        assert st["token_days_left"] >= 360  # token itself is still far off
