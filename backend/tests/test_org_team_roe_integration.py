"""
Phase 1.1 — Integration tests for Organization, Team, and ROE APIs.
"""

import pytest
from fastapi.testclient import TestClient

from ._license_test_utils import license_ee

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
USER_PASS = "OrgPass1234!"

_s: dict = {}


def _login(c: TestClient, username: str, password: str = USER_PASS):
    r = c.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, f"login failed for {username}: {r.text}"


def _logout(c: TestClient):
    c.post("/api/auth/logout")


def _create_user(c: TestClient, username: str):
    r = c.post(
        "/api/admin/users",
        json={
            "username": username,
            "password": USER_PASS,
            "role": "user",
        },
    )
    assert r.status_code in (200, 201), f"create user {username}: {r.text}"
    return r.json()["id"]


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient, module_db):
    c = module_client
    c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    _login(c, ADMIN, ADMIN_PASS)
    # These tests use the 'analyst' role as a tool for checking org-level
    # visibility, and the client-facing review roles are Team+
    # (docs/modules/MONETIZATION.md). A license, not an `ee` marker: the
    # roles exist in a Community build too, they are gated by the license
    # rather than removed from the artifact.
    _s["_license_undo"] = license_ee(c, module_db)
    _s["uid1"] = _create_user(c, "org_user1")
    _s["uid2"] = _create_user(c, "org_user2")

    r = c.post(
        "/api/projects",
        json={"name": "ROE Test", "added": "2025-01-01T00:00:00Z", "status": "active"},
    )
    _s["pid"] = r.json()["id"]

    c.post(f"/api/projects/{_s['pid']}/members", json={"user_id": _s["uid1"], "role": "operator"})
    yield
    _s.pop("_license_undo")()
    c.post("/api/auth/logout")


# ── Organization ─────────────────────────────────────────────────────


class TestOrganizationCRUD:
    def test_create_org(self, module_client: TestClient):
        r = module_client.post("/api/orgs", json={"name": "Test Org", "slug": "test-org"})
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["name"] == "Test Org"
        assert data["slug"] == "test-org"
        _s["org_id"] = data["id"]
        # This module exercises org/team/ROE RBAC, not plan-tier limits —
        # it adds/removes more members than the Free tier's cap (3) across
        # its test sequence, so it needs an unlimited-members plan.
        r = module_client.patch(f"/api/marketplace/plans/{_s['org_id']}", json={"tier": "enterprise"})
        assert r.status_code == 200, r.text

    def test_list_orgs(self, module_client: TestClient):
        r = module_client.get("/api/orgs")
        assert r.status_code == 200
        assert any(o["id"] == _s["org_id"] for o in r.json())

    def test_get_org(self, module_client: TestClient):
        r = module_client.get(f"/api/orgs/{_s['org_id']}")
        assert r.status_code == 200
        assert r.json()["id"] == _s["org_id"]

    def test_update_org(self, module_client: TestClient):
        r = module_client.patch(f"/api/orgs/{_s['org_id']}", json={"name": "Updated Org"})
        assert r.status_code == 200
        assert r.json()["name"] == "Updated Org"

    def test_invalid_slug(self, module_client: TestClient):
        r = module_client.post("/api/orgs", json={"name": "Bad", "slug": "INVALID SLUG!"})
        assert r.status_code == 400

    def test_duplicate_slug(self, module_client: TestClient):
        r = module_client.post("/api/orgs", json={"name": "Dup", "slug": "test-org"})
        assert r.status_code == 409

    def test_non_member_cannot_see_org(self, module_client: TestClient):
        _logout(module_client)
        _login(module_client, "org_user2")
        r = module_client.get(f"/api/orgs/{_s['org_id']}")
        assert r.status_code == 403
        _logout(module_client)
        _login(module_client, ADMIN, ADMIN_PASS)


class TestOrganizationMembers:
    def test_creator_is_owner(self, module_client: TestClient):
        r = module_client.get(f"/api/orgs/{_s['org_id']}/members")
        assert r.status_code == 200
        members = r.json()
        assert len(members) >= 1
        assert any(m["role"] == "owner" for m in members)

    def test_add_member(self, module_client: TestClient):
        r = module_client.post(
            f"/api/orgs/{_s['org_id']}/members", json={"user_id": _s["uid1"], "role": "viewer"}
        )
        assert r.status_code == 201
        assert r.json()["role"] == "viewer"

    def test_member_cannot_add_others(self, module_client: TestClient):
        _logout(module_client)
        _login(module_client, "org_user1")
        r = module_client.post(
            f"/api/orgs/{_s['org_id']}/members", json={"user_id": _s["uid2"], "role": "viewer"}
        )
        assert r.status_code == 403
        _logout(module_client)
        _login(module_client, ADMIN, ADMIN_PASS)

    def test_remove_member(self, module_client: TestClient):
        r = module_client.delete(f"/api/orgs/{_s['org_id']}/members/{_s['uid1']}")
        assert r.status_code == 204


class TestOrgUserCreation:
    """Org owner/admin/manager/team_lead can onboard new accounts straight
    into their own org without needing platform_admin (2026-08-18)."""

    def test_owner_can_create_user(self, module_client: TestClient):
        r = module_client.post(
            f"/api/orgs/{_s['org_id']}/users",
            json={"username": "org_created_by_owner", "password": USER_PASS, "role": "viewer"},
        )
        assert r.status_code == 201, r.text
        assert r.json()["role"] == "viewer"

    def test_created_user_is_never_platform_admin(self, module_client: TestClient):
        module_client.post(
            f"/api/orgs/{_s['org_id']}/users",
            json={
                "username": "org_created_check_role",
                "password": USER_PASS,
                "role": "admin",
            },
        )
        r = module_client.get("/api/admin/users")
        u = next(x for x in r.json() if x["username"] == "org_created_check_role")
        assert u["role"] == "user"

    def test_manager_role_can_create_user(self, module_client: TestClient):
        module_client.post(
            f"/api/orgs/{_s['org_id']}/members",
            json={"user_id": _s["uid2"], "role": "manager"},
        )
        _logout(module_client)
        _login(module_client, "org_user2")
        r = module_client.post(
            f"/api/orgs/{_s['org_id']}/users",
            json={"username": "org_created_by_manager", "password": USER_PASS, "role": "viewer"},
        )
        assert r.status_code == 201, r.text
        _logout(module_client)
        _login(module_client, ADMIN, ADMIN_PASS)
        module_client.delete(f"/api/orgs/{_s['org_id']}/members/{_s['uid2']}")

    def test_plain_viewer_cannot_create_user(self, module_client: TestClient):
        r = module_client.post(
            f"/api/orgs/{_s['org_id']}/members",
            json={"user_id": _s["uid1"], "role": "viewer"},
        )
        assert r.status_code == 201
        _logout(module_client)
        _login(module_client, "org_user1")
        r = module_client.post(
            f"/api/orgs/{_s['org_id']}/users",
            json={"username": "org_created_by_viewer", "password": USER_PASS, "role": "viewer"},
        )
        assert r.status_code == 403
        _logout(module_client)
        _login(module_client, ADMIN, ADMIN_PASS)
        module_client.delete(f"/api/orgs/{_s['org_id']}/members/{_s['uid1']}")

    def test_team_lead_cannot_grant_admin_role(self, module_client: TestClient):
        # A team_lead creating a fresh "admin" account would be a
        # privilege escalation — the grant ceiling must reject any role
        # outranking the caller's own, not just "owner" specifically.
        module_client.post(
            f"/api/orgs/{_s['org_id']}/members",
            json={"user_id": _s["uid1"], "role": "team_lead"},
        )
        _logout(module_client)
        _login(module_client, "org_user1")
        r = module_client.post(
            f"/api/orgs/{_s['org_id']}/users",
            json={"username": "org_escalation_attempt", "password": USER_PASS, "role": "admin"},
        )
        assert r.status_code == 403
        _logout(module_client)
        _login(module_client, ADMIN, ADMIN_PASS)
        module_client.delete(f"/api/orgs/{_s['org_id']}/members/{_s['uid1']}")

    def test_non_owner_cannot_grant_owner_role(self, module_client: TestClient):
        module_client.post(
            f"/api/orgs/{_s['org_id']}/members",
            json={"user_id": _s["uid1"], "role": "admin"},
        )
        _logout(module_client)
        _login(module_client, "org_user1")
        r = module_client.post(
            f"/api/orgs/{_s['org_id']}/users",
            json={"username": "org_created_wants_owner", "password": USER_PASS, "role": "owner"},
        )
        assert r.status_code == 403
        _logout(module_client)
        _login(module_client, ADMIN, ADMIN_PASS)
        module_client.delete(f"/api/orgs/{_s['org_id']}/members/{_s['uid1']}")


# ── Teams ────────────────────────────────────────────────────────────


class TestTeamCRUD:
    def test_create_team(self, module_client: TestClient):
        if "org_id" not in _s:
            r = module_client.post("/api/orgs", json={"name": "Team Org", "slug": "team-org"})
            assert r.status_code == 201, r.text
            _s["org_id"] = r.json()["id"]
        r = module_client.post(f"/api/orgs/{_s['org_id']}/teams", json={"name": "Red Team"})
        assert r.status_code == 201, r.text
        _s["team_id"] = r.json()["id"]

    def test_list_teams(self, module_client: TestClient):
        r = module_client.get(f"/api/orgs/{_s['org_id']}/teams")
        assert r.status_code == 200
        assert any(t["id"] == _s["team_id"] for t in r.json())

    def test_add_team_member(self, module_client: TestClient):
        module_client.post(
            f"/api/orgs/{_s['org_id']}/members", json={"user_id": _s["uid1"], "role": "viewer"}
        )
        r = module_client.post(
            f"/api/orgs/{_s['org_id']}/teams/{_s['team_id']}/members",
            json={"user_id": _s["uid1"], "role": "viewer"},
        )
        assert r.status_code == 201

    def test_list_team_members(self, module_client: TestClient):
        r = module_client.get(f"/api/orgs/{_s['org_id']}/teams/{_s['team_id']}/members")
        assert r.status_code == 200
        assert any(m["user_id"] == _s["uid1"] for m in r.json())

    def test_remove_team_member(self, module_client: TestClient):
        r = module_client.delete(
            f"/api/orgs/{_s['org_id']}/teams/{_s['team_id']}/members/{_s['uid1']}"
        )
        assert r.status_code == 204

    def test_delete_team(self, module_client: TestClient):
        r = module_client.delete(f"/api/orgs/{_s['org_id']}/teams/{_s['team_id']}")
        assert r.status_code == 204


# ── ROE ──────────────────────────────────────────────────────────────


class TestROE:
    def test_get_empty_roe(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_s['pid']}/roe")
        assert r.status_code == 200
        assert r.json()["allowed_activities"] == []

    def test_upsert_roe(self, module_client: TestClient):
        r = module_client.put(
            f"/api/projects/{_s['pid']}/roe",
            json={
                "allowed_activities": ["web_scanning", "ad_recon"],
                "forbidden_activities": ["dos"],
                "work_hours_start": "09:00",
                "work_hours_end": "18:00",
                "timezone": "Europe/Moscow",
                "max_scan_rate": "100",
                "requires_approval": ["destructive"],
                "emergency_contacts": [{"name": "Lead", "phone": "+1-555"}],
                "notes": "Standard engagement",
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["allowed_activities"] == ["web_scanning", "ad_recon"]
        assert data["forbidden_activities"] == ["dos"]
        assert data["work_hours_start"] == "09:00"
        assert data["emergency_contacts"] == [{"name": "Lead", "phone": "+1-555"}]
        _s["roe_id"] = data["id"]

    def test_get_roe_after_upsert(self, module_client: TestClient):
        r = module_client.get(f"/api/projects/{_s['pid']}/roe")
        assert r.status_code == 200
        assert r.json()["allowed_activities"] == ["web_scanning", "ad_recon"]

    def test_update_roe(self, module_client: TestClient):
        r = module_client.put(
            f"/api/projects/{_s['pid']}/roe",
            json={
                "allowed_activities": ["web_scanning", "ad_recon", "exploitation"],
                "forbidden_activities": ["dos"],
                "timezone": "UTC",
            },
        )
        assert r.status_code == 200
        assert "exploitation" in r.json()["allowed_activities"]

    def test_delete_roe(self, module_client: TestClient):
        r = module_client.delete(f"/api/projects/{_s['pid']}/roe")
        assert r.status_code == 204
        r = module_client.get(f"/api/projects/{_s['pid']}/roe")
        assert r.status_code == 200
        assert r.json()["allowed_activities"] == []

    def test_operator_cannot_set_roe(self, module_client: TestClient):
        _logout(module_client)
        _login(module_client, "org_user1")
        r = module_client.put(
            f"/api/projects/{_s['pid']}/roe",
            json={
                "allowed_activities": ["everything"],
            },
        )
        assert r.status_code == 403
        _logout(module_client)
        _login(module_client, ADMIN, ADMIN_PASS)


# ── Org-based project visibility, role editing, audit trail ───────────
# (2026-08-18 access-control audit: non-admin org members had no default
# project visibility at all, org member/team lifecycle actions weren't
# audit-logged, and there was no way to edit a member's role after the
# initial add.)


class TestOrgProjectVisibilityAndRoleEdit:
    def test_attach_project_to_org(self, module_client: TestClient):
        r = module_client.post("/api/orgs", json={"name": "Vis Org", "slug": "vis-org"})
        assert r.status_code == 201, r.text
        _s["vis_org_id"] = r.json()["id"]

        r = module_client.post(
            "/api/projects",
            json={"name": "Vis Project", "added": "2025-01-01T00:00:00Z", "status": "active"},
        )
        assert r.status_code == 201
        _s["vis_pid"] = r.json()["id"]

        r = module_client.patch(
            f"/api/projects/{_s['vis_pid']}", json={"org_id": _s["vis_org_id"]}
        )
        assert r.status_code == 200, r.text
        assert r.json()["org_id"] == _s["vis_org_id"]

    def test_non_admin_org_role_sees_project_without_manual_grant(self, module_client: TestClient):
        r = module_client.post(
            f"/api/orgs/{_s['vis_org_id']}/members",
            json={"user_id": _s["uid2"], "role": "analyst"},
        )
        assert r.status_code == 201, r.text

        _logout(module_client)
        _login(module_client, "org_user2")
        try:
            r = module_client.get("/api/projects")
            assert r.status_code == 200
            assert any(p["id"] == _s["vis_pid"] for p in r.json())

            perms = module_client.get(f"/api/projects/{_s['vis_pid']}/permissions/me").json()
            assert perms["role"] == "analyst"
            assert "findings.create" in perms["permissions"]
            assert "hosts.create" not in perms["permissions"]
        finally:
            _logout(module_client)
            _login(module_client, ADMIN, ADMIN_PASS)

    def test_removing_org_member_revokes_project_visibility(self, module_client: TestClient):
        r = module_client.delete(f"/api/orgs/{_s['vis_org_id']}/members/{_s['uid2']}")
        assert r.status_code == 204

        _logout(module_client)
        _login(module_client, "org_user2")
        try:
            r = module_client.get("/api/projects")
            assert r.status_code == 200
            assert not any(p["id"] == _s["vis_pid"] for p in r.json())
        finally:
            _logout(module_client)
            _login(module_client, ADMIN, ADMIN_PASS)

    def test_patch_member_role(self, module_client: TestClient):
        r = module_client.post(
            f"/api/orgs/{_s['vis_org_id']}/members",
            json={"user_id": _s["uid1"], "role": "viewer"},
        )
        assert r.status_code == 201

        r = module_client.patch(
            f"/api/orgs/{_s['vis_org_id']}/members/{_s['uid1']}", json={"role": "manager"}
        )
        assert r.status_code == 200, r.text
        assert r.json()["role"] == "manager"

        r = module_client.get(f"/api/orgs/{_s['vis_org_id']}/members")
        assert any(m["user_id"] == _s["uid1"] and m["role"] == "manager" for m in r.json())

    def test_member_cannot_patch_role_above_own_rank(self, module_client: TestClient):
        # org_user1 is now "manager" (rank 4) in vis_org — cannot grant "admin" (rank 5)
        _logout(module_client)
        _login(module_client, "org_user1")
        try:
            r = module_client.patch(
                f"/api/orgs/{_s['vis_org_id']}/members/{_s['uid1']}", json={"role": "admin"}
            )
            assert r.status_code == 403
        finally:
            _logout(module_client)
            _login(module_client, ADMIN, ADMIN_PASS)

    def test_member_add_remove_role_change_are_audit_logged(self, module_client: TestClient):
        r = module_client.get(
            "/api/audit/log", params={"target_type": "org_member", "limit": 100}
        )
        assert r.status_code == 200
        actions = {e["action"] for e in r.json()["items"] if e["target_id"] == _s["uid1"]}
        assert "member.add" in actions
        assert "member.role_change" in actions

    def test_org_admin_sees_org_scoped_audit_entries(self, module_client: TestClient):
        # org_user1 (org "manager") should see org-scoped audit entries for
        # their own org even without any project.export/audit.read grant.
        _logout(module_client)
        _login(module_client, "org_user1")
        try:
            r = module_client.get(
                "/api/audit/log", params={"target_type": "org_member", "limit": 100}
            )
            assert r.status_code == 200
            assert any(e["target_id"] == _s["uid1"] for e in r.json()["items"])
        finally:
            _logout(module_client)
            _login(module_client, ADMIN, ADMIN_PASS)

    def test_non_org_admin_cannot_attach_project_to_org(self, module_client: TestClient):
        r = module_client.post(
            "/api/projects",
            json={"name": "Loose Project", "added": "2025-01-01T00:00:00Z", "status": "active"},
        )
        pid = r.json()["id"]
        module_client.post(f"/api/projects/{pid}/members", json={"user_id": _s["uid2"], "role": "owner"})

        _logout(module_client)
        _login(module_client, "org_user2")
        try:
            r = module_client.patch(f"/api/projects/{pid}", json={"org_id": _s["vis_org_id"]})
            assert r.status_code == 403
        finally:
            _logout(module_client)
            _login(module_client, ADMIN, ADMIN_PASS)


# ── Realtime member updates + caller's own org role on GET /api/orgs ──
# (2026-08-18: member add/remove/role-change required a manual page
# reload — nothing broadcast an event and there was no room to receive
# one on; separately, GET /api/orgs didn't return the caller's own role
# per org, which is what the frontend now uses instead of the
# *project* role to decide whether to show the org admin UI.)


class TestOrgListReturnsCallerRole:
    def test_role_field_present(self, module_client: TestClient):
        r = module_client.post("/api/orgs", json={"name": "Role Field Org", "slug": "role-field-org"})
        assert r.status_code == 201, r.text
        org_id = r.json()["id"]
        r = module_client.get("/api/orgs")
        assert r.status_code == 200
        row = next(o for o in r.json() if o["id"] == org_id)
        assert row["role"] == "owner"

    def test_non_member_role_is_absent_from_their_list(self, module_client: TestClient):
        r = module_client.post(
            "/api/admin/users", json={"username": "org_role_field_u2", "password": USER_PASS, "role": "user"}
        )
        assert r.status_code in (200, 201)
        _logout(module_client)
        _login(module_client, "org_role_field_u2")
        try:
            r = module_client.get("/api/orgs")
            assert r.status_code == 200
            assert r.json() == []
        finally:
            _logout(module_client)
            _login(module_client, ADMIN, ADMIN_PASS)


class TestOrgWebsocketRoom:
    """The `/ws/{pid}` endpoint accepts an `org:<id>` room key — same
    ConnectionManager, same broadcast(), gated on org membership (any
    role) instead of project membership."""

    def test_org_member_can_connect(self, module_client: TestClient):
        r = module_client.post("/api/orgs", json={"name": "WS Auth Org", "slug": "ws-auth-org"})
        org_id = r.json()["id"]
        with module_client.websocket_connect(f"/ws/org:{org_id}"):
            pass  # no exception on connect/accept == success

    def test_non_member_is_rejected(self, module_client: TestClient):
        r = module_client.post(
            "/api/admin/users", json={"username": "ws_non_member", "password": USER_PASS, "role": "user"}
        )
        assert r.status_code in (200, 201)
        _logout(module_client)
        _login(module_client, "ws_non_member")
        try:
            with pytest.raises(Exception):
                with module_client.websocket_connect("/ws/org:nonexistent-org-id"):
                    pass
        finally:
            _logout(module_client)
            _login(module_client, ADMIN, ADMIN_PASS)


class TestOrgMemberBroadcast:
    """Every org/team member mutation fires a bcast() to the `org:<id>`
    room — verified at the call level (mocked) rather than over a real
    socket, since the shared test-fixture DB session
    (tests/conftest.py::module_db) isn't safe to use concurrently from a
    held-open WebSocket connection and a REST call in the same test."""

    def test_add_member_broadcasts(self, module_client: TestClient, monkeypatch):
        calls = []
        monkeypatch.setattr(
            "app.routers.organizations.bcast", lambda pid, entity, action, data: calls.append((pid, entity, action, data))
        )
        r = module_client.post("/api/orgs", json={"name": "Bcast Org", "slug": "bcast-org"})
        org_id = r.json()["id"]
        r = module_client.post(
            "/api/admin/users", json={"username": "bcast_u1", "password": USER_PASS, "role": "user"}
        )
        uid = r.json()["id"]

        r = module_client.post(f"/api/orgs/{org_id}/members", json={"user_id": uid, "role": "viewer"})
        assert r.status_code == 201
        assert any(c[:3] == (f"org:{org_id}", "org_member", "add") and c[3]["user_id"] == uid for c in calls)

        calls.clear()
        r = module_client.patch(f"/api/orgs/{org_id}/members/{uid}", json={"role": "analyst"})
        assert r.status_code == 200
        assert any(c[:3] == (f"org:{org_id}", "org_member", "role_change") for c in calls)

        calls.clear()
        r = module_client.delete(f"/api/orgs/{org_id}/members/{uid}")
        assert r.status_code == 204
        assert any(c[:3] == (f"org:{org_id}", "org_member", "remove") and c[3]["user_id"] == uid for c in calls)


# ── Org delete ───────────────────────────────────────────────────────


class TestOrgDelete:
    def test_delete_org(self, module_client: TestClient):
        r = module_client.delete(f"/api/orgs/{_s['org_id']}")
        assert r.status_code == 204

    def test_org_gone(self, module_client: TestClient):
        r = module_client.get(f"/api/orgs/{_s['org_id']}")
        assert r.status_code == 404
