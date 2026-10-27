"""
ФТ-6 (docs/modules/LICENSING_TZ.md): online license heartbeat.

Licensing is per self-hosted instance, not per Organization — see
core/license.py's module docstring. Uses httpx.MockTransport to fake the
not-yet-built License Server's /v1/heartbeat responses, and a throwaway
signing keypair (same technique as test_license_ft4_ft5.py) for the
"server returns a valid token" case.
"""
import base64
import json
import time

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app.core import license as license_module
from app.core import license_heartbeat

from ._license_test_utils import reset_instance_license

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
_s: dict = {}

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


def _license_claims(fingerprint: str, **overrides) -> dict:
    claims = {
        "tier": "pro",
        "features": ["infra_lifecycle"],
        "max_members": -1,
        "max_infra_instances": -1,
        "max_workstations": -1,
        "fingerprint": fingerprint,
        "issued_at": time.time(),
        "expires_at": time.time() + 3600,
    }
    claims.update(overrides)
    return claims


def _client_that_returns(status_code: int, json_body: dict | None = None) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, json=json_body or {})

    return httpx.Client(transport=httpx.MockTransport(handler))


def _client_that_raises() -> httpx.Client:
    def handler(request: httpx.Request):
        raise httpx.ConnectError("connection refused")

    return httpx.Client(transport=httpx.MockTransport(handler))


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient, module_db):
    reset_instance_license(module_db)
    c = module_client
    c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    c.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    yield
    c.post("/api/auth/logout")
    reset_instance_license(module_db)


def _license_instance(module_client: TestClient, module_db) -> None:
    from app.core.license import get_fingerprint

    fp = get_fingerprint(module_db)
    token = _sign(_license_claims(fp))
    r = module_client.post("/api/system/license/upload", json={"token": token})
    assert r.status_code == 201, r.text


class TestNotLicensedIsNoop:
    def test_unlicensed_offline_channel_is_noop(self, module_client, module_db):
        # Only the deliberately-offline channel skips polling entirely; an
        # unlicensed ONLINE instance now polls every few minutes so a
        # vendor-bound c2v activates it automatically (see
        # test_license_auto_pickup.py for that path).
        module_client.patch("/api/system/license/channel", json={"offline": True})
        outcome = license_heartbeat.run_heartbeat(module_db, _client_that_raises())
        assert outcome == "not_licensed"
        module_client.patch("/api/system/license/channel", json={"offline": False})


class TestOfflineChannelIsSkipped:
    def test_offline_channel_skips_heartbeat(self, module_client, module_db):
        _license_instance(module_client, module_db)
        module_client.patch("/api/system/license/channel", json={"offline": True})

        outcome = license_heartbeat.run_heartbeat(module_db, _client_that_raises())
        assert outcome == "offline_channel"

        module_client.patch("/api/system/license/channel", json={"offline": False})


class TestHeartbeatOutcomes:
    def test_unreachable_does_not_downgrade(self, module_db):
        # Heartbeat no longer downgrades on network failure — the lifecycle
        # (license_state) treats a >7-day-stale heartbeat as the lapse.
        outcome = license_heartbeat.run_heartbeat(module_db, _client_that_raises())
        assert outcome == "unreachable"
        r_tier = module_db.query(license_heartbeat.models.OrganizationPlan).first()
        assert r_tier is None or r_tier.tier == "pro"

    def test_server_reachable_with_valid_token_renews(self, module_client, module_db):
        from app.core.license import get_fingerprint

        fp = get_fingerprint(module_db)
        new_token = _sign(_license_claims(fp, tier="enterprise", features=["sso"]))
        client = _client_that_returns(200, {"token": new_token})
        outcome = license_heartbeat.run_heartbeat(module_db, client)
        assert outcome == "renewed"

        r = module_client.post("/api/orgs", json={"name": "HB Renew Org", "slug": "hb-renew-org"})
        org_id = r.json()["id"]
        r = module_client.get(f"/api/marketplace/plans/{org_id}")
        assert r.json()["tier"] == "enterprise"

    def test_server_reports_inactive_starts_grace_not_instant_free(self, module_client, module_db):
        from app.core.license_state import get_license_status

        client = _client_that_returns(200, {"status": "inactive"})
        outcome = license_heartbeat.run_heartbeat(module_db, client)
        assert outcome == "inactive"

        # revoked_at is stamped, so the lifecycle enters grace (not an
        # instant drop to Free) — tier is retained during grace.
        state = license_heartbeat.get_instance_license_state(module_db)
        assert state.revoked_at is not None
        assert get_license_status(module_db)["state"] == "grace"

        r = module_client.post("/api/orgs", json={"name": "HB Inactive Org", "slug": "hb-inactive-org"})
        org_id = r.json()["id"]
        r = module_client.get(f"/api/marketplace/plans/{org_id}")
        assert r.json()["tier"] == "enterprise"

        # re-license to clear revoked_at for any later classes
        _license_instance(module_client, module_db)


class TestHeartbeatPass:
    def test_pass_returns_empty_when_not_licensed_or_offline(self, module_db):
        # After the previous class's "inactive" downgrade, the instance
        # still HAS a LicenseToken (the license simply lapsed) — so this
        # exercises the offline-channel empty-result path instead.
        state = license_heartbeat.get_instance_license_state(module_db)
        state.license_offline = True
        module_db.commit()
        results = license_heartbeat.run_heartbeat_pass(module_db)
        assert results == {}
        state.license_offline = False
        module_db.commit()


class TestSignedCheckin:
    """LICENSING_REDESIGN Phase 3: the heartbeat sends a signed check-in the
    License Server can authenticate."""

    def test_heartbeat_sends_verifiable_signed_checkin(self, module_client, module_db):
        _license_instance(module_client, module_db)
        from app.core.instance_identity import verify_instance_signature
        from app.core.license import get_fingerprint

        captured: dict = {}

        def handler(request):
            captured["body"] = json.loads(request.content)
            token = _sign(_license_claims(get_fingerprint(module_db)))
            return httpx.Response(200, json={"token": token})

        client = httpx.Client(transport=httpx.MockTransport(handler))
        outcome = license_heartbeat.run_heartbeat(module_db, client)
        assert outcome == "renewed"

        b = captured["body"]
        assert b.get("instance_pubkey") and b.get("signature") and b.get("ts")
        assert "hwid" in b
        # the signature proves possession of the instance key over "fp:ts"
        msg = f"{b['fingerprint']}:{b['ts']}".encode()
        assert verify_instance_signature(b["instance_pubkey"], msg, b["signature"])
