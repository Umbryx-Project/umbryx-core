"""main.py window coverage: auth middleware hardening + lifecycle units.

Shannon 2026-10-29 / external review changes that shipped without
focused tests: query-string JWT rejection (AUTH-01), webhook-GET no
longer public (AUTH-06), session-revocation checks on stream tokens,
project-owner backfill, C2 auto-sync failure tracking and the global
presence endpoint."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.core.security import make_stream_token
from app.main import (
    _C2_SYNC_FAILURES,
    _authenticate_download_request,
    _backfill_project_owners,
    _c2_sync_one_integration,
)

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
TS = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient, module_db):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200, r.text
    from app import models as m

    _state["admin"] = module_db.query(m.User).filter_by(username=ADMIN).first()
    yield
    module_client.post("/api/auth/logout")


class TestAuthMiddlewareHardening:
    def test_query_string_jwt_rejected(self, module_client: TestClient):
        module_client.post("/api/auth/logout")
        r = module_client.get("/api/projects?token=anything")
        assert r.status_code == 401
        assert "Query-string tokens" in r.text
        module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})

    def test_webhook_get_is_not_public(self, module_client: TestClient):
        # AUTH-06: only the POST ingest is public; the token check GET
        # must go through authentication like any other API route
        module_client.post("/api/auth/logout")
        r = module_client.get("/api/webhooks/some-token")
        assert r.status_code == 401
        r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
        assert r.status_code == 200

    def test_stream_token_only_on_stream_routes(self, module_client: TestClient):
        tok = make_stream_token(_state["admin"])
        module_client.post("/api/auth/logout")
        r = module_client.get(f"/api/projects?token={tok}")
        assert r.status_code == 401
        assert "streaming endpoints" in r.text
        module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})

    async def test_revoked_session_kills_stream_token(self, module_client: TestClient):
        tok = make_stream_token(_state["admin"])
        module_client.post("/api/auth/logout")
        with patch("app.main.user_sessions_revoked", new=AsyncMock(return_value=True)):
            r = module_client.get(f"/api/projects/prj_x/jobs/job_y/output-stream?token={tok}")
            assert r.status_code == 401
            assert "revoked" in r.text.lower()
        module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})


class TestBackfillProjectOwners:
    def test_ownerless_project_gets_admin_owner(self, module_client: TestClient, module_db):
        from app import models as m
        from app.core.enums import MemberRole
        from app.core.utils import new_id, ts_now

        pid = new_id("prj")
        module_db.add(m.Project(id=pid, name="backfill-me", added=ts_now()))
        module_db.commit()

        _backfill_project_owners(module_db)
        owner = (
            module_db.query(m.ProjectMember)
            .filter(
                m.ProjectMember.project_id == pid,
                m.ProjectMember.role == MemberRole.OWNER,
                m.ProjectMember.is_active.is_(True),
            )
            .first()
        )
        assert owner is not None
        assert owner.user_id == _state["admin"].id

        # idempotent: second run adds nothing
        _backfill_project_owners(module_db)
        count = (
            module_db.query(m.ProjectMember)
            .filter(m.ProjectMember.project_id == pid, m.ProjectMember.role == MemberRole.OWNER)
            .count()
        )
        assert count == 1

        module_db.query(m.ProjectMember).filter(m.ProjectMember.project_id == pid).delete()
        module_db.query(m.Project).filter(m.Project.id == pid).delete()
        module_db.commit()


class TestC2SyncOneIntegration:
    async def test_success_clears_failure_counter(self):
        _C2_SYNC_FAILURES["it1"] = 2
        with patch("app.routers.c2._do_project_sync", new=AsyncMock(return_value=None)) as sync:
            await _c2_sync_one_integration(
                {"id": "it1", "name": "cfg", "project_ids": ["p1"]}, db=MagicMock(), _now=None
            )
            assert sync.await_count == 1
        assert "it1" not in _C2_SYNC_FAILURES

    async def test_timeout_increments_failure_counter(self):

        _C2_SYNC_FAILURES.pop("it2", None)
        with patch("app.routers.c2._do_project_sync", new=AsyncMock(side_effect=TimeoutError())):
            await _c2_sync_one_integration(
                {"id": "it2", "name": "cfg", "project_ids": ["p1"]}, db=MagicMock(), _now=None
            )
        assert _C2_SYNC_FAILURES["it2"] == 1
        _C2_SYNC_FAILURES.pop("it2", None)


class TestPresenceEndpoint:
    def test_global_presence_shape(self, module_client: TestClient):
        r = module_client.get("/api/presence")
        assert r.status_code == 200, r.text
        assert "online" in r.json()


class TestAuthenticateDownloadRequest:
    """Downloads legitimately accept ?token= (unlike API routes)."""

    def _req(self, headers=None, cookies=None, qs=None):
        req = MagicMock()
        req.headers = headers or {}
        req.cookies = cookies or {}
        req.query_params = qs or {}
        return req

    async def test_no_token_401(self, module_db):
        user, resp = await _authenticate_download_request(self._req(), module_db)
        assert user is None and resp.status_code == 401

    async def test_garbage_token_401(self, module_db):
        req = self._req(qs={"token": "garbage"})
        user, resp = await _authenticate_download_request(req, module_db)
        assert user is None
        assert resp.status_code == 401

    async def test_valid_qs_token_accepted(self, module_db):
        req = self._req(qs={"token": "fake.jwt.value"})
        payload = {
            "sub": _state["admin"].id,
            "username": ADMIN,
            "role": "platform_admin",
            "jti": "j-1",
            "iat": 200,
        }
        with (
            patch("app.main.decode_access_token", return_value=payload),
            patch("app.main.is_blacklisted", new=AsyncMock(return_value=False)),
            patch("app.main.user_sessions_revoked", new=AsyncMock(return_value=False)),
        ):
            user, resp = await _authenticate_download_request(req, module_db)
        assert resp is None
        assert user.username == ADMIN

    async def test_revoked_session_401(self, module_db):
        req = self._req(qs={"token": "fake.jwt.value"})
        payload = {"sub": _state["admin"].id, "jti": "j-2", "iat": 100}
        with (
            patch("app.main.decode_access_token", return_value=payload),
            patch("app.main.is_blacklisted", new=AsyncMock(return_value=False)),
            patch("app.main.user_sessions_revoked", new=AsyncMock(return_value=True)),
        ):
            user, resp = await _authenticate_download_request(req, module_db)
        assert user is None
        assert resp.status_code == 401
