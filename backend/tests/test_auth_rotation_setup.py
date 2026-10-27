"""Refresh token rotation + SETUP_TOKEN guard for /api/auth/setup (release 1.0.0 audit)."""

from unittest.mock import patch

from app import models as m
from app.core.enums import UserRole
from app.core.security import hash_password
from app.core.utils import new_id, ts_now


class _MemBlacklist:
    def __init__(self):
        self.revoked = {}

    async def blacklist(self, jti, exp):
        self.revoked[jti] = exp

    async def check(self, jti):
        return jti in self.revoked


def _ensure_admin(db):
    if not db.query(m.User).filter_by(username="admin").first():
        db.add(
            m.User(
                id=new_id("u"),
                username="admin",
                display_name="admin",
                password_hash=hash_password("TestPass1234!"),
                role=UserRole.PLATFORM_ADMIN,
                created_at=ts_now(),
                active=True,
            )
        )
        db.commit()


def test_refresh_rotation_kills_old_token(module_client, module_db):
    bl = _MemBlacklist()
    with patch("app.routers.auth.blacklist_token", bl.blacklist), patch(
        "app.routers.auth.is_blacklisted", bl.check
    ):
        r1 = module_client.post("/api/auth/refresh", json={"refresh_token": "bogus"})
        assert r1.status_code == 401  # malformed → no leak

        admin = module_db.query(m.User).filter_by(username="admin").first()
        assert admin is not None
        from app.core.security import make_refresh_token

        rt1 = make_refresh_token(admin)

        r2 = module_client.post("/api/auth/refresh", json={"refresh_token": rt1})
        assert r2.status_code == 200
        rt2 = r2.json()["refresh_token"]
        assert rt2 and rt2 != rt1
        assert bl.revoked, "old jti must be blacklisted on rotation"

        # the rotated-out token is now dead
        r3 = module_client.post("/api/auth/refresh", json={"refresh_token": rt1})
        assert r3.status_code == 401
        # the fresh one still works and rotates again
        r4 = module_client.post("/api/auth/refresh", json={"refresh_token": rt2})
        assert r4.status_code == 200
        r5 = module_client.post("/api/auth/refresh", json={"refresh_token": rt2})
        assert r5.status_code == 401


def _snapshot_admin(db):
    a = db.query(m.User).filter_by(username="admin").first()
    return {c: getattr(a, c) for c in ("id", "username", "display_name", "password_hash", "role", "active")} if a else None


def _restore_admin(db, snap):
    if not snap:
        return
    db.add(m.User(created_at=ts_now(), **snap))
    db.commit()


def test_setup_requires_token_when_configured(module_client, module_db, monkeypatch):
    snap = _snapshot_admin(module_db)
    monkeypatch.setenv("SETUP_TOKEN", "s3cret-boot-token")
    module_db.query(m.User).delete()
    module_db.commit()
    try:
        # wrong token
        r = module_client.post(
            "/api/auth/setup",
            json={"username": "root", "password": "Str0ngPassw0rd!", "setup_token": "nope"},
        )
        assert r.status_code == 401
        # missing token
        r = module_client.post(
            "/api/auth/setup", json={"username": "root", "password": "Str0ngPassw0rd!"}
        )
        assert r.status_code == 401
        # correct token claims admin
        r = module_client.post(
            "/api/auth/setup",
            json={
                "username": "root",
                "password": "Str0ngPassw0rd!",
                "setup_token": "s3cret-boot-token",
            },
        )
        assert r.status_code == 201
    finally:
        module_db.query(m.User).delete()
        module_db.commit()
        _restore_admin(module_db, snap)
        monkeypatch.delenv("SETUP_TOKEN")


def test_setup_without_env_open_as_before(module_client, module_db, monkeypatch):
    snap = _snapshot_admin(module_db)
    monkeypatch.delenv("SETUP_TOKEN", raising=False)
    module_db.query(m.User).delete()
    module_db.commit()
    try:
        r = module_client.post(
            "/api/auth/setup", json={"username": "root", "password": "Str0ngPassw0rd!"}
        )
        assert r.status_code == 201
    finally:
        module_db.query(m.User).delete()
        module_db.commit()
        _restore_admin(module_db, snap)
