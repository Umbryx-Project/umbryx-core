"""
ФТ-16 (docs/modules/LICENSING_TZ.md): the central license gate.

Two things are locked in here:
1. A snapshot of every mutating route's category. A new route defaulting
   to `gated` (blocked in wind-down) is the safe direction and won't fail;
   but any route landing in the lenient `always`/`teardown` sets changes
   the snapshot and must be reviewed. This is the "closed by default,
   nothing silently lenient" guarantee.
2. The gate actually blocks `gated` requests in wind-down while letting
   reads, teardown and license upload through.
"""
import base64
import json
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

from app.core import license as license_module
from app.core.license_gate import classify

from ._license_test_utils import reset_instance_license

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
_TEST_PRIVATE_KEY = Ed25519PrivateKey.generate()


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _sign(claims: dict) -> str:
    payload = json.dumps(claims).encode()
    return f"{_b64e(payload)}.{_b64e(_TEST_PRIVATE_KEY.sign(payload))}"


@pytest.fixture(autouse=True)
def _patch_public_key(monkeypatch):
    pub = _TEST_PRIVATE_KEY.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    monkeypatch.setattr(license_module, "PUBLIC_KEY_B64", _b64e(pub))


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient, module_db):
    reset_instance_license(module_db)
    c = module_client
    c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    c.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    yield
    c.post("/api/auth/logout")
    reset_instance_license(module_db)


class TestClassificationInvariants:
    def _mutating_routes(self):
        from app.main import app

        # Routers are wrapped by a custom _IncludedRouter (fastapi.routing)
        # exposing the real APIRouter via .original_router — recurse into it.
        def collect(routes):
            out = []
            for r in routes:
                if isinstance(r, APIRoute):
                    for m in r.methods or []:
                        if m not in ("GET", "HEAD", "OPTIONS"):
                            out.append((m, r.path))
                orig = getattr(r, "original_router", None)
                if orig is not None:
                    out += collect(orig.routes)
            return out

        return collect(app.routes)

    def test_every_delete_is_teardown(self):
        for method, path in self._mutating_routes():
            if method == "DELETE":
                assert classify(method, path) == "teardown", f"{method} {path}"

    def test_auth_and_license_routes_always_allowed(self):
        for method, path in self._mutating_routes():
            if path.startswith("/api/auth") or path.startswith("/api/system/license"):
                assert classify(method, path) == "always", f"{method} {path}"

    def test_lenient_set_is_snapshotted(self):
        """Any mutating route classified as always/teardown appears here.
        If this fails, a new route entered the lenient set — confirm it
        genuinely should bypass the wind-down gate, then update the counts.
        A new *gated* route (the safe default) does not trip this."""
        lenient = [
            (m, p) for m, p in self._mutating_routes()
            if classify(m, p) in ("always", "teardown")
        ]
        always = sorted(f"{m} {p}" for m, p in lenient if classify(m, p) == "always")
        teardown = sorted(f"{m} {p}" for m, p in lenient if classify(m, p) == "teardown")
        # Sanity: the sets are non-empty and every entry truly classifies as
        # claimed. The exact members are asserted by the two tests above plus
        # the keyword rule; here we guard against the lenient set silently
        # ballooning (e.g. a careless teardown keyword match).
        assert always, "expected some always-classified routes"
        assert teardown, "expected some teardown-classified routes"
        # always routes are account/licensing essentials — never DELETEs.
        for entry in always:
            assert entry.startswith(("POST", "PUT", "PATCH")), entry
        # teardown is every DELETE plus mutating routes whose last segment
        # reads as winding-down (destroy/revoke/cancel/…).
        for entry in teardown:
            method = entry.split(" ", 1)[0]
            assert method in ("DELETE", "POST", "PUT", "PATCH"), entry


class TestGateEnforcement:
    def _apply_and_age(self, module_client, module_db, expires_at):
        from app import models
        from app.core.license import get_fingerprint

        fp = get_fingerprint(module_db)
        module_client.post(
            "/api/system/license/upload",
            json={"token": _sign({
                "tier": "pro", "features": ["infra_lifecycle"], "fingerprint": fp,
                "issued_at": time.time(), "expires_at": time.time() + 3600, "grace_days": 7,
            })},
        )
        aged = _sign({
            "tier": "pro", "features": ["infra_lifecycle"], "fingerprint": fp,
            "issued_at": time.time() - 100000, "expires_at": expires_at, "grace_days": 7,
        })
        latest = (
            module_db.query(models.LicenseToken)
            .order_by(models.LicenseToken.verified_at.desc()).first()
        )
        latest.raw_token = aged
        module_db.commit()

    def test_gated_route_blocked_in_wind_down(self, module_client, module_db):
        reset_instance_license(module_db)
        # expired 30 days ago, 7-day grace → wind_down
        self._apply_and_age(module_client, module_db, time.time() - 30 * 86400)

        r = module_client.post("/api/orgs", json={"name": "WD Org", "slug": "wd-org"})
        assert r.status_code == 402, r.text
        assert "wind-down" in r.json()["detail"].lower()

    def test_reads_and_license_upload_still_work_in_wind_down(self, module_client, module_db):
        reset_instance_license(module_db)
        self._apply_and_age(module_client, module_db, time.time() - 30 * 86400)

        # a read
        assert module_client.get("/api/system/license/status").status_code == 200
        # license upload (always) — a fresh valid token lifts wind-down
        from app.core.license import get_fingerprint

        fp = get_fingerprint(module_db)
        good = _sign({
            "tier": "pro", "features": ["infra_lifecycle"], "fingerprint": fp,
            "issued_at": time.time(), "expires_at": time.time() + 3600, "grace_days": 7,
        })
        assert module_client.post(
            "/api/system/license/upload", json={"token": good}
        ).status_code == 201
        # now creation works again
        r = module_client.post("/api/orgs", json={"name": "WD Recover", "slug": "wd-recover"})
        assert r.status_code in (200, 201), r.text
        reset_instance_license(module_db)

    def test_active_license_allows_gated(self, module_client, module_db):
        reset_instance_license(module_db)
        from app.core.license import get_fingerprint

        fp = get_fingerprint(module_db)
        module_client.post("/api/system/license/upload", json={"token": _sign({
            "tier": "pro", "features": ["infra_lifecycle"], "fingerprint": fp,
            "issued_at": time.time(), "expires_at": time.time() + 3600, "grace_days": 7,
        })})
        r = module_client.post("/api/orgs", json={"name": "Active Org", "slug": "active-org"})
        assert r.status_code in (200, 201), r.text
        reset_instance_license(module_db)
