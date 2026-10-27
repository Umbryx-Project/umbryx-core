"""
ФТ-8 (docs/modules/LICENSING_TZ.md): anti-tamper reconciliation.

Licensing is per self-hosted instance, not per Organization — see
core/license.py's module docstring. Simulates a self-hosted admin editing
organization_plans directly (the attack this whole check exists to catch)
by mutating an OrganizationPlan row through the ORM after a valid
instance-wide license was already applied, then verifying
run_reconciliation_pass() reverts it — and that a licensed instance's
expiry downgrades every org, not just one.
"""
import base64
import json
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app.core import license as license_module
from app.core import license_reconciliation

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


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient, module_db):
    reset_instance_license(module_db)
    c = module_client
    c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    c.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    yield
    c.post("/api/auth/logout")
    reset_instance_license(module_db)


def _license_instance(module_client: TestClient, module_db, **claim_overrides) -> None:
    from app.core.license import get_fingerprint

    fp = get_fingerprint(module_db)
    claims = {
        "tier": "pro",
        "features": ["infra_lifecycle", "workstations"],
        "max_members": -1,
        "max_infra_instances": -1,
        "max_workstations": -1,
        "fingerprint": fp,
        "issued_at": time.time(),
        "expires_at": time.time() + 3600,
    }
    claims.update(claim_overrides)
    token = _sign(claims)
    r = module_client.post("/api/system/license/upload", json={"token": token})
    assert r.status_code == 201, r.text


def _make_org(module_client: TestClient, slug: str) -> str:
    r = module_client.post("/api/orgs", json={"name": slug, "slug": slug})
    assert r.status_code in (200, 201), r.text
    org_id = r.json()["id"]
    # Touch the marketplace endpoint so ensure_org_plan() actually creates
    # the OrganizationPlan row now — tests that grab it directly via the
    # ORM right after this need it to already exist.
    module_client.get(f"/api/marketplace/plans/{org_id}")
    return org_id


class TestNeverLicensedIsNoop:
    def test_unlicensed_instance_reconciliation_is_noop(self, module_client, module_db):
        org_id = _make_org(module_client, "recon-manual")
        module_client.patch(f"/api/marketplace/plans/{org_id}", json={"tier": "enterprise"})
        module_db.expire_all()

        results = license_reconciliation.run_reconciliation_pass(module_db)
        assert results == {}

        r = module_client.get(f"/api/marketplace/plans/{org_id}")
        assert r.json()["tier"] == "enterprise"


class TestMatchingPlansStayOk:
    def test_all_orgs_matching_license_is_ok(self, module_client, module_db):
        _license_instance(module_client, module_db)
        org_a = _make_org(module_client, "recon-ok-a")
        org_b = _make_org(module_client, "recon-ok-b")
        module_db.expire_all()

        results = license_reconciliation.run_reconciliation_pass(module_db)
        # recon-manual (previous class) is now also licensed pro via sync —
        # confirm every org matches, nothing reverted.
        assert results.get("reverted", 0) == 0
        for org_id in (org_a, org_b):
            r = module_client.get(f"/api/marketplace/plans/{org_id}")
            assert r.json()["tier"] == "pro"


class TestTamperDetection:
    def test_tier_edited_directly_is_reverted(self, module_client, module_db):
        org_id = _make_org(module_client, "recon-tier-tamper")
        plan = module_db.query(license_reconciliation.models.OrganizationPlan).filter_by(
            org_id=org_id
        ).first()
        # Simulate a self-hosted admin editing the DB row directly.
        plan.tier = "enterprise"
        plan.features = ["sso", "infra_lifecycle"]
        module_db.commit()

        results = license_reconciliation.run_reconciliation_pass(module_db)
        assert results.get("reverted", 0) >= 1

        module_db.refresh(plan)
        assert plan.tier == "pro"
        assert "sso" not in plan.features

    def test_limits_edited_directly_is_reverted(self, module_client, module_db):
        org_id = _make_org(module_client, "recon-limits-tamper")
        plan = module_db.query(license_reconciliation.models.OrganizationPlan).filter_by(
            org_id=org_id
        ).first()
        plan.max_members = 9999
        module_db.commit()

        license_reconciliation.run_reconciliation_pass(module_db)

        module_db.refresh(plan)
        assert plan.max_members == -1  # pro tier's max_members from the license

    def test_logs_security_event_on_tamper(self, module_client, module_db):
        org_id = _make_org(module_client, "recon-tamper-log")
        plan = module_db.query(license_reconciliation.models.OrganizationPlan).filter_by(
            org_id=org_id
        ).first()
        plan.tier = "free"
        module_db.commit()

        before = (
            module_db.query(license_reconciliation.models.SystemLog)
            .filter_by(category="security", event="license.tamper_detected")
            .count()
        )
        license_reconciliation.run_reconciliation_pass(module_db)
        after = (
            module_db.query(license_reconciliation.models.SystemLog)
            .filter_by(category="security", event="license.tamper_detected")
            .count()
        )
        assert after > before


class TestExpiryKeepsTierThroughGrace:
    def _age_token_to(self, module_db, expires_at: float, grace_days: int = 14):
        """Re-sign the stored token with a past expiry, writing raw_token
        directly — simulates wall-clock time passing beyond the license's
        expiry without going through the upload endpoint (which refuses an
        already-expired file). get_instance_entitlement re-verifies the
        signature, so the re-signed token must be validly signed."""
        from app.core.license import get_fingerprint

        fp = get_fingerprint(module_db)
        aged = _sign(
            {
                "tier": "pro",
                "features": ["infra_lifecycle", "workstations"],
                "max_members": -1,
                "max_infra_instances": -1,
                "max_workstations": -1,
                "fingerprint": fp,
                "issued_at": time.time() - 100000,
                "expires_at": expires_at,
                "grace_days": grace_days,
            }
        )
        latest = license_reconciliation._latest_token(module_db)
        latest.raw_token = aged
        module_db.commit()

    def test_expired_within_grace_does_not_downgrade(self, module_client, module_db):
        _license_instance(module_client, module_db)  # valid pro token
        org_a = _make_org(module_client, "recon-grace-a")
        org_b = _make_org(module_client, "recon-grace-b")
        # Age it: expired 2 days ago, 14-day grace → grace state.
        self._age_token_to(module_db, time.time() - 2 * 86400)
        module_db.expire_all()

        results = license_reconciliation.run_reconciliation_pass(module_db)
        assert "expired" not in results

        # C1: tier retained through grace, not dropped to Free.
        for org_id in (org_a, org_b):
            r = module_client.get(f"/api/marketplace/plans/{org_id}")
            assert r.json()["tier"] == "pro"

    def test_state_reports_grace_then_wind_down(self, module_db):
        from app.core.license_state import get_license_status

        self._age_token_to(module_db, time.time() - 2 * 86400, grace_days=14)
        assert get_license_status(module_db)["state"] == "grace"

        self._age_token_to(module_db, time.time() - 30 * 86400, grace_days=14)
        assert get_license_status(module_db)["state"] == "wind_down"

        # Restore a valid token: the instance license state is a singleton
        # shared by every later module in the run, and leaving wind_down
        # here made /api/marketplace/plans answer 402 ("license has
        # lapsed") in whichever module touched tier gates next — an
        # order/timing flake that surfaced in test_plan_enforcement_wiring
        # (found while stabilizing the Postgres CI runs, 2026-10-13).
        self._age_token_to(module_db, time.time() + 3600, grace_days=14)
        assert get_license_status(module_db)["state"] == "active"
