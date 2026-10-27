"""Online key activation endpoint — the backend exchanges the pasted
UMBR- key plus this instance's C2V identity for a signed token with the
license server, server-to-server. The HTTP call is mocked; everything
after it (signature + binding verification, token persistence) runs for
real."""
import base64
import json
import time

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from app.core import hwid as hwid_mod
from app.core import license as lic
from app.core.instance_identity import instance_public_key_b64
from app.core.license import get_or_create_install_uuid
from app.routers import license_admin

from ._license_test_utils import reset_instance_license

_KEY = Ed25519PrivateKey.generate()


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


@pytest.fixture(scope="module", autouse=True)
def _login_admin(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": "admin", "password": "TestPass1234!"})
    r = module_client.post("/api/auth/login", json={"username": "admin", "password": "TestPass1234!"})
    assert r.status_code == 200, r.text


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


class _FakeResp:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload


def test_activate_online_happy_path(db, module_client: TestClient, monkeypatch):
    captured = {}

    def fake_post(url, json=None, timeout=None):
        captured["url"] = url
        captured["c2v"] = json
        iu = get_or_create_install_uuid(db)
        claims = {
            "tier": "enterprise",
            "features": ["sso", "multiple_orgs"],
            "issued_at": time.time(),
            "expires_at": time.time() + 365 * 86400,
            "hwid": hwid_mod.current_hwid_hashes(iu),
            "instance_pubkey": instance_public_key_b64(db),
            "nonce": json["nonce"],
        }
        return _FakeResp({"status": "ok", "token": _sign(claims)})

    monkeypatch.setattr(license_admin.httpx, "post", fake_post)

    r = module_client.post("/api/system/license/activate", json={"license_key": "UMBR-TEST-KEY-0001"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["tier"] == "enterprise"
    # the license server got the key + the full C2V identity
    assert captured["url"].endswith("/v1/activate")
    assert captured["c2v"]["license_key"] == "UMBR-TEST-KEY-0001"
    assert captured["c2v"]["instance_pubkey"]
    assert captured["c2v"]["hwid"]


def test_activate_online_maps_already_bound(db, module_client: TestClient, monkeypatch):
    monkeypatch.setattr(
        license_admin.httpx, "post", lambda *a, **k: _FakeResp({"status": "already_bound"})
    )
    r = module_client.post("/api/system/license/activate", json={"license_key": "UMBR-X"})
    assert r.status_code == 409
    assert "bound to another device" in r.json()["detail"]


def test_activate_online_maps_invalid_key(db, module_client: TestClient, monkeypatch):
    monkeypatch.setattr(
        license_admin.httpx, "post", lambda *a, **k: _FakeResp({"status": "invalid_key"})
    )
    r = module_client.post("/api/system/license/activate", json={"license_key": "UMBR-X"})
    assert r.status_code == 400
    assert "not accepted" in r.json()["detail"]


def test_activate_online_unreachable(db, module_client: TestClient, monkeypatch):
    def boom(*a, **k):
        raise httpx.ConnectError("no route")

    monkeypatch.setattr(license_admin.httpx, "post", boom)
    r = module_client.post("/api/system/license/activate", json={"license_key": "UMBR-X"})
    assert r.status_code == 502
