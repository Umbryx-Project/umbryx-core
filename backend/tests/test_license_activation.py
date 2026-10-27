"""Offline activation handshake — C2V export + binding checks on import
(LICENSING_REDESIGN Phase 2, core/license.py + hwid + instance_identity)."""
import base64
import json
import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core import hwid as hwid_mod
from app.core import license as lic
from app.core.instance_identity import instance_public_key_b64
from app.core.license import (
    LicenseVerificationError,
    apply_license_token,
    build_activation_request,
    get_fingerprint,
    get_or_create_install_uuid,
)

from ._license_test_utils import reset_instance_license

_KEY = Ed25519PrivateKey.generate()


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _sign(claims: dict) -> str:
    payload = json.dumps(claims).encode()
    return f"{_b64e(payload)}.{_b64e(_KEY.sign(payload))}"


@pytest.fixture(autouse=True)
def _patch_key_and_reset(monkeypatch, db):
    pub = _KEY.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    monkeypatch.setattr(lic, "PUBLIC_KEY_B64", _b64e(pub))
    reset_instance_license(db)
    lic._set_pending_activation(db, None)
    yield
    reset_instance_license(db)


def _claims(db, **over):
    iu = get_or_create_install_uuid(db)
    c = {
        "tier": "pro",
        "features": ["api_access"],
        "issued_at": time.time(),
        "expires_at": time.time() + 365 * 86400,
        "hwid": hwid_mod.current_hwid_hashes(iu),
        "instance_pubkey": instance_public_key_b64(db),
    }
    c.update(over)
    return c


def test_activation_request_has_hwid_key_and_nonce(db):
    req = build_activation_request(db)
    assert req["product"] == "umbryx" and req["format_version"] == 1
    assert req["nonce"] and req["instance_pubkey"]
    assert "install_uuid" in req["hwid"]  # at least the anchor is always present
    assert lic._get_pending_activation(db)["nonce"] == req["nonce"]  # stored pending


def test_import_hwid_bound_token_succeeds(db):
    claims = apply_license_token(db, _sign(_claims(db)))
    assert claims["tier"] == "pro"


def test_import_rejects_clone(db):
    iu = get_or_create_install_uuid(db)
    bound = dict(hwid_mod.current_hwid_hashes(iu))
    # Force clone-sensitive params that current can't match (a snapshot clone):
    bound["product_uuid"] = "d" * 64
    bound["primary_mac"] = "e" * 64
    with pytest.raises(LicenseVerificationError, match="Hardware identity"):
        apply_license_token(db, _sign(_claims(db, hwid=bound)))


def test_import_rejects_wrong_instance_key(db):
    with pytest.raises(LicenseVerificationError, match="instance key"):
        apply_license_token(db, _sign(_claims(db, instance_pubkey="AAAA")))


def test_legacy_fingerprint_token_still_works(db):
    # An old token with only a single fingerprint (no hwid/pubkey) still applies.
    c = {
        "tier": "pro", "features": ["api_access"], "issued_at": time.time(),
        "expires_at": time.time() + 3600, "fingerprint": get_fingerprint(db),
    }
    assert apply_license_token(db, _sign(c))["tier"] == "pro"


def test_nonce_mismatch_rejected(db):
    build_activation_request(db)  # sets a pending nonce
    with pytest.raises(LicenseVerificationError, match="activation request"):
        apply_license_token(db, _sign(_claims(db, nonce="a-different-nonce")))


def test_matching_nonce_accepted_and_pending_cleared(db):
    req = build_activation_request(db)
    claims = apply_license_token(db, _sign(_claims(db, nonce=req["nonce"])))
    assert claims["tier"] == "pro"
    assert lic._get_pending_activation(db) in (None, {})  # consumed
