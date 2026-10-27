"""
Phase 1.2 — Integration tests for project invitation system.
"""
import pytest
from fastapi.testclient import TestClient

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
USER_PASS = "InvitePass1234!"

_s: dict = {}


def _login(c: TestClient, username: str, password: str = USER_PASS):
    r = c.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, f"login failed for {username}: {r.text}"


def _logout(c: TestClient):
    c.post("/api/auth/logout")


def _create_user(c: TestClient, username: str):
    r = c.post("/api/admin/users", json={"username": username, "password": USER_PASS, "role": "user"})
    assert r.status_code in (200, 201), f"create user {username}: {r.text}"
    return r.json()["id"]


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    c = module_client
    c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    _login(c, ADMIN, ADMIN_PASS)
    r = c.post("/api/projects", json={"name": "Invite Test", "added": "2025-01-01T00:00:00Z", "status": "active"})
    _s["pid"] = r.json()["id"]
    _s["uid_invitee"] = _create_user(c, "invite_target")
    _s["uid_outsider"] = _create_user(c, "invite_outsider")
    yield
    c.post("/api/auth/logout")


class TestInvitationCreate:
    def test_create_invitation(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_s['pid']}/invitations", json={"role": "operator", "expires_hours": 48})
        assert r.status_code == 201
        data = r.json()
        assert data["role"] == "operator"
        assert data["revoked"] is False
        assert data["accepted_at"] is None
        assert len(data["token"]) == 32
        _s["inv_id"] = data["id"]
        _s["token"] = data["token"]

    def test_list_invitations(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_s['pid']}/invitations")
        assert r.status_code == 200
        assert any(i["id"] == _s["inv_id"] for i in r.json())

    def test_invalid_role(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_s['pid']}/invitations", json={"role": "nonexistent"})
        assert r.status_code == 400

    def test_operator_cannot_invite(self, module_client: TestClient):
        _logout(module_client)
        _login(module_client, "invite_outsider")
        module_client.post(f"/api/projects/{_s['pid']}/members", json={"user_id": _s["uid_outsider"], "role": "operator"})
        r = module_client.post(f"/api/projects/{_s['pid']}/invitations", json={"role": "viewer"})
        assert r.status_code == 403
        _logout(module_client)
        _login(module_client, ADMIN, ADMIN_PASS)


class TestInvitationAccept:
    def test_accept_invitation(self, module_client: TestClient):
        _logout(module_client)
        _login(module_client, "invite_target")
        r = module_client.post("/api/projects/accept-invite", json={"token": _s["token"]})
        assert r.status_code == 200
        data = r.json()
        assert data["project_id"] == _s["pid"]
        assert data["role"] == "operator"
        _logout(module_client)
        _login(module_client, ADMIN, ADMIN_PASS)

    def test_acceptee_is_now_member(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_s['pid']}/members")
        assert r.status_code == 200
        members = r.json()
        assert any(m["user_id"] == _s["uid_invitee"] and m["role"] == "operator" for m in members)

    def test_cannot_reuse_token(self, module_client: TestClient):
        _logout(module_client)
        _login(module_client, "invite_outsider")
        r = module_client.post("/api/projects/accept-invite", json={"token": _s["token"]})
        assert r.status_code == 404
        _logout(module_client)
        _login(module_client, ADMIN, ADMIN_PASS)

    def test_invalid_token(self, module_client: TestClient):
        _logout(module_client)
        _login(module_client, "invite_target")
        r = module_client.post("/api/projects/accept-invite", json={"token": "nonexistent"})
        assert r.status_code == 404
        _logout(module_client)
        _login(module_client, ADMIN, ADMIN_PASS)


class TestInvitationRevoke:
    def test_create_and_revoke(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_s['pid']}/invitations", json={"role": "viewer"})
        assert r.status_code == 201
        inv_id = r.json()["id"]

        r = module_client.post(f"/api/projects/{_s['pid']}/invitations/{inv_id}/revoke")
        assert r.status_code == 200

        r = module_client.get(f"/api/projects/{_s['pid']}/invitations")
        assert not any(i["id"] == inv_id for i in r.json())

    def test_cannot_accept_revoked(self, module_client: TestClient):
        r = module_client.post(f"/api/projects/{_s['pid']}/invitations", json={"role": "viewer"})
        token = r.json()["token"]
        inv_id = r.json()["id"]
        module_client.post(f"/api/projects/{_s['pid']}/invitations/{inv_id}/revoke")

        _logout(module_client)
        _login(module_client, "invite_outsider")
        r = module_client.post("/api/projects/accept-invite", json={"token": token})
        assert r.status_code == 404
        _logout(module_client)
        _login(module_client, ADMIN, ADMIN_PASS)
