"""Outbound proxy: setting API + env application for all egress."""

import os


def _admin_login(client):
    client.post("/api/auth/login", json={"username": "admin", "password": "TestPass1234!"})


def test_get_defaults_empty(module_client):
    _admin_login(module_client)
    r = module_client.get("/api/admin/outbound-proxy")
    assert r.status_code == 200
    assert r.json() == {}


def test_put_validates_urls(module_client):
    _admin_login(module_client)
    r = module_client.put(
        "/api/admin/outbound-proxy", json={"http": "not a url"}
    )
    assert r.status_code == 400


def test_put_applies_env_roundtrip(module_client):
    _admin_login(module_client)
    r = module_client.put(
        "/api/admin/outbound-proxy",
        json={"http": "http://proxy.corp:3128", "https": "http://proxy.corp:3128"},
    )
    assert r.status_code == 200 and r.json()["ok"] is True
    assert os.environ.get("HTTP_PROXY") == "http://proxy.corp:3128"
    assert os.environ.get("NO_PROXY")
    r = module_client.get("/api/admin/outbound-proxy")
    assert r.json()["http"] == "http://proxy.corp:3128"
    # disable
    r = module_client.put("/api/admin/outbound-proxy", json={})
    assert r.status_code == 200
    assert r.json()["outbound_proxy"] == {}


def test_requires_admin(module_client, module_db):
    # unauthenticated — not 200
    import starlette.testclient as _tc

    anon = _tc.TestClient(module_client.app)
    assert anon.get("/api/admin/outbound-proxy").status_code == 401


def test_socks5_scheme_allowed(module_client):
    _admin_login(module_client)
    r = module_client.put(
        "/api/admin/outbound-proxy", json={"http": "socks5://127.0.0.1:1080"}
    )
    assert r.status_code == 200
    module_client.put("/api/admin/outbound-proxy", json={})
