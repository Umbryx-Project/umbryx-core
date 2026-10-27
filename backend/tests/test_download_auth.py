"""Tests for GET /api/uploads/{pid}/{path} — the authenticated file-download
endpoint in app.main.

Regression: _authenticate_download_request only ever checked an
Authorization header or a ?token= query param — but /api/auth/login only
ever sets an httpOnly cookie (no access_token is returned to the client to
put in a header), and /api/auth/refresh needs a refresh_token that's
likewise never issued. The frontend's downloadUrl() has always assumed
cookie auth ("cookie auth handles authentication for download links",
frontend/src/api/index.ts) — every download link 401'd for every real user
(security retest, 2026-09-03).
"""

import pytest
from fastapi.testclient import TestClient

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _setup(module_client):
    module_client.post("/api/auth/setup", json={"username": "admin", "password": "TestPass1234!"})
    r = module_client.post(
        "/api/auth/login", json={"username": "admin", "password": "TestPass1234!"}
    )
    assert r.status_code == 200, f"login failed: {r.status_code} {r.text}"
    r = module_client.post(
        "/api/projects",
        json={"name": "Download Auth Test Proj", "added": "2025-01-01T00:00:00Z", "status": "active"},
    )
    assert r.status_code in (201, 409), f"project: {r.status_code} {r.text}"
    if r.status_code == 201:
        _state["pid"] = r.json()["id"]
    else:
        ps = module_client.get("/api/projects").json()
        _state["pid"] = next(p["id"] for p in ps if p["name"] == "Download Auth Test Proj")

    r = module_client.post(
        "/api/notes",
        json={"pid": _state["pid"], "title": "dl-test", "content": "x", "ts": "2025-01-01T00:00:00Z"},
    )
    assert r.status_code == 201, r.text
    _state["nid"] = r.json()["id"]

    r = module_client.post(
        f"/api/notes/{_state['nid']}/attachments",
        files={"file": ("report.txt", b"hello world", "text/plain")},
    )
    assert r.status_code == 201, r.text
    _state["public_url"] = r.json()["public_url"]
    yield


class TestDownloadCookieAuth:
    def test_download_via_cookie_succeeds(self, module_client: TestClient):
        # module_client carries only the httpOnly session cookie set by
        # login — no Authorization header — exactly what a browser <a href>
        # click sends. This is the case that 401'd before the fix.
        r = module_client.get(_state["public_url"])
        assert r.status_code == 200, r.text
        assert r.content == b"hello world"

    def test_download_without_any_auth_still_401s(self, client: TestClient):
        # A fresh, unauthenticated client (no cookie, no header) must still
        # be rejected — the fix adds cookie support, it doesn't remove auth.
        r = client.get(_state["public_url"])
        assert r.status_code == 401

    def test_download_with_bearer_header_still_works(self, module_client: TestClient):
        # Explicit Authorization header must keep working (e.g. non-browser
        # API clients), unaffected by adding cookie support.
        me = module_client.get("/api/auth/me")
        assert me.status_code == 200
        cookie_token = module_client.cookies.get("rt_auth")
        assert cookie_token
        r = module_client.get(
            _state["public_url"], headers={"Authorization": f"Bearer {cookie_token}"}
        )
        assert r.status_code == 200
