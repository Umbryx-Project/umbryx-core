"""Tests for the per-instance keypair (core/instance_identity.py, Phase 1c)."""
from app.core import instance_identity as ii


def test_keypair_is_stable_across_calls(db):
    pub1 = ii.instance_public_key_b64(db)
    pub2 = ii.instance_public_key_b64(db)
    assert pub1 == pub2 and len(pub1) >= 40  # persisted, not regenerated


def test_sign_and_verify_roundtrip(db):
    pub = ii.instance_public_key_b64(db)
    sig = ii.sign_with_instance_key(db, b"challenge-nonce")
    assert ii.verify_instance_signature(pub, b"challenge-nonce", sig)
    # wrong data or wrong key fails, and never raises
    assert not ii.verify_instance_signature(pub, b"tampered", sig)
    assert not ii.verify_instance_signature("not-a-key", b"challenge-nonce", sig)


def test_regenerates_from_corrupt_row(db):
    from app import models
    pub1 = ii.instance_public_key_b64(db)
    row = db.get(models.GlobalSetting, "instance_privkey")
    row.value = {"sk": "!!!not-valid!!!"}
    db.commit()
    pub2 = ii.instance_public_key_b64(db)  # must recover, not raise
    assert pub2 and pub2 != pub1


def test_fingerprint_endpoint_exposes_instance_pubkey(client):
    # setup + login as admin, then hit the admin-only fingerprint endpoint
    client.post("/api/auth/setup", json={"username": "admin", "password": "TestPass1234!"})
    client.post("/api/auth/login", json={"username": "admin", "password": "TestPass1234!"})
    r = client.get("/api/system/license/fingerprint")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("instance_pubkey") and body.get("fingerprint")
