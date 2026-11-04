"""notes: confidential-content gating and the pid-less listing paths."""

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
MEMBER = "notes_member"
MEMBER_PASS = "Pass1234!notes"
TS = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient, module_db):
    module_client.post(
        "/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS}
    )  # NOSONAR
    assert (
        module_client.post(
            "/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS}
        ).status_code
        == 200
    )
    r = module_client.post(
        "/api/admin/users", json={"username": MEMBER, "password": MEMBER_PASS, "role": "user"}
    )
    assert r.status_code in (201, 409)
    r = module_client.post("/api/projects", json={"name": "Notes Listing", "added": TS})
    assert r.status_code in (200, 201), r.text
    _state["pid"] = r.json()["id"]
    yield
    module_client.post("/api/auth/logout")


def _mk_note(module_client, tags):
    # notes are created via the global /api/notes with pid in the body
    r = module_client.post(
        "/api/notes",
        json={
            "pid": _state["pid"],
            "title": "conf note",
            "content": "secret-words",
            "tags": tags,
            "ts": TS,
        },
    )
    assert r.status_code in (200, 201), r.text
    return r.json()["id"]


class TestConfidentialGating:
    def test_confidential_note_content_restricted_for_member(self, module_client, module_db):

        # direct row: a confidential note owned with content encrypted
        _mk_note(module_client, ["confidential"])
        # the restriction branch needs a caller WITHOUT credentials.read_secret:
        # a plain project member (viewer role lacks it)
        users = module_client.get("/api/admin/users").json()
        member_id = next(u["id"] for u in users if u["username"] == MEMBER)
        r = module_client.post(
            f"/api/projects/{_state['pid']}/members", json={"user_id": member_id, "role": "viewer"}
        )
        assert r.status_code in (200, 201, 409)
        module_client.post("/api/auth/logout")
        assert (
            module_client.post(
                "/api/auth/login", json={"username": MEMBER, "password": MEMBER_PASS}
            ).status_code
            == 200
        )
        r = module_client.get(f"/api/notes?pid={_state['pid']}")
        assert r.status_code == 200, r.text
        notes = r.json()
        conf = [n for n in notes if n.get("title") == "conf note"]
        assert conf and conf[0]["content"] == "[restricted: credentials.read_secret required]"
        module_client.post("/api/auth/logout")
        module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})

    def test_listing_without_pid_admin_and_member_paths(self, module_client):
        # admin path: every non-deleted note across projects
        r = module_client.get("/api/notes")
        assert r.status_code == 200
        assert "X-Total-Count" in r.headers
        # member path: only notes of pids the caller belongs to
        module_client.post("/api/auth/logout")
        module_client.post("/api/auth/login", json={"username": MEMBER, "password": MEMBER_PASS})
        r = module_client.get("/api/notes")
        assert r.status_code == 200
        titles = {n["title"] for n in r.json()}
        assert "conf note" in titles  # viewer of the project → its notes,
        # with the confidential content still restricted
        for n in r.json():
            assert n["content"] != "secret-words"
        module_client.post("/api/auth/logout")
        module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})


class TestHealthEndpoint:
    def test_health_public_shape(self, module_client: TestClient):
        r = module_client.get("/api/health")
        assert r.status_code == 200
        body = r.json()
        assert body.get("status") == "ok" or "status" in body
