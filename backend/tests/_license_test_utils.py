"""
Shared helper for the licensing test modules (test_license_ft4_ft5.py,
test_license_heartbeat.py, test_license_reconciliation.py).

Licensing is instance-wide, not per-org (core/license.py's module
docstring) — LicenseToken and InstanceLicenseState are true singletons
with no org dimension to scope test data by. The test suite's DB is
shared across every test module in one pytest run (see conftest.py:
Base.metadata.create_all/drop_all run once for the whole session, not per
module), so without an explicit reset, one license test file's leftover
global state (an applied "pro" token, an offline channel flag) would leak
into every file that runs after it — including unrelated ones like
test_plan_enforcement_wiring.py, which assumes a brand-new org starts at
Free. Each license test module must call this at both setup and teardown.
"""
import base64
import json
import time

from app import models


def reset_instance_license(db):
    db.query(models.LicenseToken).delete()
    db.query(models.InstanceLicenseState).delete()
    db.commit()


def license_instance(module_client, module_db, monkeypatch, tier="pro", features=None, **claims):
    """Apply a signed instance license for tests that need a paid tier to
    reach a gated endpoint. Generates a throwaway Ed25519 keypair, patches
    the verifier's public key to match, and uploads a token bound to this
    instance's fingerprint. Returns nothing — the instance is licensed on
    return."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from app.core import license as license_module
    from app.core.license import get_fingerprint

    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    monkeypatch.setattr(license_module, "PUBLIC_KEY_B64", base64.urlsafe_b64encode(pub).decode().rstrip("="))

    payload = {
        "tier": tier,
        "features": features if features is not None else _tier_features(tier),
        "fingerprint": get_fingerprint(module_db),
        "issued_at": time.time(),
        "expires_at": time.time() + 3600,
        "grace_days": 14,
    }
    payload.update(claims)
    raw = json.dumps(payload).encode()
    sig = key.sign(raw)
    token = f"{base64.urlsafe_b64encode(raw).decode().rstrip('=')}.{base64.urlsafe_b64encode(sig).decode().rstrip('=')}"
    r = module_client.post("/api/system/license/upload", json={"token": token})
    assert r.status_code == 201, r.text


def _tier_features(tier):
    from app.core.plan import TIER_LIMITS

    return [str(f) for f in TIER_LIMITS.get(tier, TIER_LIMITS["free"])["features"]]


def license_ee(module_client, module_db, tier="enterprise"):
    """License this module's instance as Enterprise; returns an undo callable.

    For test modules that exercise deployment — infra stacks, workstation
    and pool provisioning. Deployment is Enterprise-only (see
    docs/modules/EDITIONS.md): on an unlicensed instance the routers answer
    402, so a module testing *how* a deploy behaves has to be licensed
    first, the same way a real customer is.

    Call it from the module's bootstrap fixture **after** logging in — the
    license upload endpoint requires a platform admin — and call the
    returned undo at teardown. The undo is not optional: instance license
    state is a singleton shared by every module in the pytest run (see this
    module's docstring), so a leaked Enterprise token would silently grant
    deployment to modules that assert Free behaviour.
    """
    import pytest

    mp = pytest.MonkeyPatch()
    license_instance(module_client, module_db, mp, tier=tier)

    def undo():
        mp.undo()
        reset_instance_license(module_db)

    return undo
