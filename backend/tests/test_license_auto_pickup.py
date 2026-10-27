"""Unlicensed instances poll the license server: while no license is bound
to their c2v the answer is a quiet 'awaiting_license' (no grace clock, no
security-event noise); the moment the server returns a token it is applied
and reported as the FIRST activation — the 'vendor binds the c2v, instance
picks the license up automatically' flow."""
import base64
import json
import time

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.core import hwid as hwid_mod
from app.core import license as lic
from app.core.instance_identity import instance_public_key_b64
from app.core.license import get_or_create_install_uuid
from app.core.license_heartbeat import run_heartbeat

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
    yield
    reset_instance_license(db)


class _FakeClient:
    def __init__(self, payload):
        self._payload = payload

    def post(self, *a, **k):
        resp = httpx.Response(200, request=httpx.Request("POST", "x"))
        resp._content = json.dumps(self._payload).encode()
        return resp


def test_unlicensed_poll_is_quiet_while_waiting(db):
    from app.core.license_state import get_instance_license_state

    out = run_heartbeat(db, _FakeClient({"status": "inactive"}))
    assert out == "awaiting_license"
    # no grace clock, no security noise for a never-licensed instance
    state = get_instance_license_state(db)
    assert state.revoked_at is None


def test_token_from_server_activates_automatically(db):
    iu = get_or_create_install_uuid(db)
    claims = {
        "tier": "enterprise",
        "features": ["sso"],
        "issued_at": time.time(),
        "expires_at": time.time() + 365 * 86400,
        "hwid": hwid_mod.current_hwid_hashes(iu),
        "instance_pubkey": instance_public_key_b64(db),
    }
    token = _sign(claims)
    out = run_heartbeat(db, _FakeClient({"status": "ok", "token": token}))
    assert out == "activated"
    from app.core.plan import get_instance_entitlement

    assert get_instance_entitlement(db)["tier"] == "enterprise"
