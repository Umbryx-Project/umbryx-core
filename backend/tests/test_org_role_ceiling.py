"""Org-role grant ceiling regression (2026-10-20 audit).

Org roles fall back 1:1 into PROJECT roles (core/access.py::
_resolve_role). Editor is project-senior to manager and team_lead, so
the grant ceiling must rank editor above them — otherwise a team_lead
(or manager) grants an org-editor membership whose project fallback
outranks the granter on every org project.
"""

import uuid

import pytest

from app.core.security import hash_password
from app.core.utils import ts_now
from app.models import Organization, OrganizationMember, User

PASSWORD = "TestPass1234!"  # NOSONAR


@pytest.fixture()
def ceiling_env(db):
    suffix = uuid.uuid4().hex[:8]
    org_id = f"ceorg_{suffix}"
    db.add(Organization(id=org_id, name="CE", slug=f"ce-{suffix}", created_at=ts_now()))
    db.commit()

    ids = {}

    def mk(key, org_role):
        uid = f"{key}_{suffix}"
        db.add(
            User(
                id=uid,
                username=uid,
                email=f"{uid}@t.local",
                role="user",
                active=True,
                password_hash=hash_password(PASSWORD),
                created_at=ts_now(),
            )
        )
        db.add(
            OrganizationMember(
                id=f"cm_{key}{suffix}",
                org_id=org_id,
                user_id=uid,
                role=org_role,
                created_at=ts_now(),
            )
        )
        db.commit()
        ids[key] = uid

    mk("tl", "team_lead")
    mk("mgr", "manager")
    mk("adm", "admin")
    return {"org_id": org_id, "ids": ids, "suffix": suffix}


def login(client, username):
    r = client.post("/api/auth/login", json={"username": username, "password": PASSWORD})
    assert r.status_code == 200, r.text


class TestGrantCeiling:
    def test_team_lead_cannot_grant_editor(self, client, db, ceiling_env):
        ev = ceiling_env
        login(client, ev["ids"]["tl"])
        r = client.post(
            f"/api/orgs/{ev['org_id']}/users",
            json={
                "username": f"esc_{ev['suffix']}",
                "password": PASSWORD,
                "email": f"esc_{ev['suffix']}@t.local",
                "role": "editor",
            },
        )
        # editor's project fallback outranks the team_lead granter
        assert r.status_code == 403, r.text

    def test_manager_cannot_grant_editor(self, client, db, ceiling_env):
        ev = ceiling_env
        login(client, ev["ids"]["mgr"])
        r = client.post(
            f"/api/orgs/{ev['org_id']}/users",
            json={
                "username": f"esc2_{ev['suffix']}",
                "password": PASSWORD,
                "email": f"esc2_{ev['suffix']}@t.local",
                "role": "editor",
            },
        )
        assert r.status_code == 403, r.text

    def test_admin_can_grant_editor(self, client, db, ceiling_env):
        ev = ceiling_env
        login(client, ev["ids"]["adm"])
        r = client.post(
            f"/api/orgs/{ev['org_id']}/users",
            json={
                "username": f"ok_{ev['suffix']}",
                "password": PASSWORD,
                "email": f"ok_{ev['suffix']}@t.local",
                "role": "editor",
            },
        )
        assert r.status_code in (200, 201), r.text

    def test_team_lead_can_grant_weaker_roles(self, client, db, ceiling_env):
        ev = ceiling_env
        login(client, ev["ids"]["tl"])
        # analyst/reviewer/etc are paid roles — 402 on an unlicensed
        # instance (tier gate, independent of the ceiling); base roles
        # below team_lead pass the ceiling
        for role in ("operator", "viewer"):
            r = client.post(
                f"/api/orgs/{ev['org_id']}/users",
                json={
                    "username": f"w_{role}_{ev['suffix']}",
                    "password": PASSWORD,
                    "email": f"w_{role}_{ev['suffix']}@t.local",
                    "role": role,
                },
            )
            assert r.status_code in (200, 201), (role, r.text)
