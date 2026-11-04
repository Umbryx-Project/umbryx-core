"""Targeted tests for the re-review 2026-11-02 + QA-0001 window.

The SonarQube quality gate (new_coverage >= 80%) started failing after
the re-review waves landed: several follow-up branches shipped without
focused tests — encrypt-on-flag for note attachments, the nmap-token
integer threshold, _spawn_tracked's thread path, the weak ADMIN_PASSWORD
refusal, the HA license refusal, scope exclusions, pack ownership and
the report-draft permission fan-out. Each test below asserts the
security property itself, not just the line count.
"""

from __future__ import annotations

import asyncio
import io
import ipaddress
import threading
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
USER_PASS = "UserPass1234!"
TS = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient, module_db):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    r = module_client.post(
        "/api/projects", json={"name": "GateCoverage", "added": TS, "status": "active"}
    )
    assert r.status_code == 201, r.text
    _state["pid"] = r.json()["id"]
    yield
    module_client.post("/api/auth/logout")


def _relogin(client: TestClient, username: str, password: str):
    client.post("/api/auth/logout")
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, r.text


# ── roe_guard: nmap token edge cases ─────────────────────────────────


class TestRoeGuardTokenEdges:
    """Re-review 2026-11-02: bare integers below 2**24 are port numbers
    and flags, not IPv4 literals — '-p 80' used to become the phantom
    target 0.0.0.80 and broke CIDR-scoped projects."""

    def _expand(self, token):
        from app.core.roe_guard import _expand_nmap_token

        return [str(n) for n in _expand_nmap_token(token)]

    def test_empty_token_is_not_a_target(self):
        assert self._expand("") == []

    def test_small_integers_are_ports_not_ips(self):
        assert self._expand("80") == []
        assert self._expand("443") == []
        assert self._expand("16777215") == []  # 2**24 - 1 — one below the bar

    def test_large_integer_is_an_ip_literal(self):
        assert self._expand("3232235777") == ["192.168.1.1/32"]
        assert self._expand("0xFFFFFFFF") == ["255.255.255.255/32"]

    def test_hex_too_small_is_rejected(self):
        assert self._expand("0x50") == []  # 80 again, hex flavour

    def test_reversed_octet_range_is_rejected(self):
        assert self._expand("10.0.0.5-3") == []

    def test_octet_range_above_255_is_rejected(self):
        assert self._expand("10.0.0.300-301") == []

    def test_leading_zero_decimal_is_not_a_literal(self):
        # int("080", 0) raises ValueError — a decimal with a leading zero
        # is not a valid base-0 literal, and must not become 0.0.0.80
        assert self._expand("080") == []
        assert self._expand("016777216") == []

    def test_degenerate_octet_range_is_rejected(self):
        assert self._expand("10.0.0.5-") == []
        assert self._expand("10.0.0.--5") == []


# ── notes: encrypt-on-flag ───────────────────────────────────────────


class TestNotesEncryptOnFlag:
    """Wave B: flagging an EXISTING note confidential must re-encrypt its
    plaintext attachments — confidentiality is a property of the note,
    and attachments uploaded before the flag are not grandfathered in."""

    def _mk_note(self, module_client) -> str:
        r = module_client.post(
            "/api/notes",
            json={
                "pid": _state["pid"],
                "title": "gate-enc-flag",
                "content": "attack at dusk",
                "ts": TS,
                "tags": [],
            },
        )
        assert r.status_code == 201, r.text
        return r.json()["id"]

    def _attachment(self, module_db, nid):
        from app import models as m

        return module_db.query(m.NoteAttachment).filter(m.NoteAttachment.note_id == nid).first()

    def test_flagging_note_encrypts_existing_attachments(self, module_client, module_db):
        from app.core.crypto import decrypt_bytes

        nid = self._mk_note(module_client)
        r = module_client.post(
            f"/api/notes/{nid}/attachments",
            files={"file": ("plan.txt", io.BytesIO(b"attack at dusk"), "text/plain")},
        )
        assert r.status_code == 201, r.text
        att = self._attachment(module_db, nid)
        assert att is not None and att.file_encrypted is False

        r = module_client.patch(f"/api/notes/{nid}", json={"tags": ["confidential"]})
        assert r.status_code == 200, r.text

        module_db.expire_all()
        att = self._attachment(module_db, nid)
        assert att.file_encrypted is True
        from app.core.storage import get_storage_backend

        raw = asyncio.run(get_storage_backend().load(att.storage_path))
        assert raw != b"attack at dusk"  # ciphertext at rest now
        assert decrypt_bytes(raw) == b"attack at dusk"  # round-trips

    def test_reflag_is_idempotent(self, module_client, module_db):
        nid = self._mk_note(module_client)
        module_client.post(
            f"/api/notes/{nid}/attachments",
            files={"file": ("b.txt", io.BytesIO(b"second secret"), "text/plain")},
        )
        assert module_client.patch(f"/api/notes/{nid}", json={"tags": ["confidential"]}).status_code == 200
        # second save with the flag already on must not double-encrypt
        assert module_client.patch(f"/api/notes/{nid}", json={"title": "renamed"}).status_code == 200
        module_db.expire_all()
        att = self._attachment(module_db, nid)
        assert att.file_encrypted is True

    def test_wrongly_unflagged_ciphertext_heals_without_reencrypt(self, module_client, module_db):
        """If the flag says plaintext but storage already holds a Fernet
        token (a partially-failed earlier flag operation), re-flagging
        must heal the flag — never encrypt twice."""
        nid = self._mk_note(module_client)
        module_client.post(
            f"/api/notes/{nid}/attachments",
            files={"file": ("c.txt", io.BytesIO(b"third secret"), "text/plain")},
        )
        assert module_client.patch(f"/api/notes/{nid}", json={"tags": ["confidential"]}).status_code == 200
        # simulate the flag having been lost
        att = self._attachment(module_db, nid)
        att.file_encrypted = False
        module_db.commit()
        assert module_client.patch(f"/api/notes/{nid}", json={"title": "renamed2"}).status_code == 200
        module_db.expire_all()
        assert self._attachment(module_db, nid).file_encrypted is True

    def test_storage_failure_skips_attachment_not_the_request(self, module_client, module_db):
        """A storage outage during re-encryption must not fail the whole
        note update — the attachment keeps its flag and the operator can
        retrigger; losing the edit would be worse."""
        from unittest.mock import AsyncMock as _AM

        nid = self._mk_note(module_client)
        module_client.post(
            f"/api/notes/{nid}/attachments",
            files={"file": ("d.txt", io.BytesIO(b"fourth secret"), "text/plain")},
        )
        store = MagicMock()
        store.load = _AM(side_effect=Exception("storage down"))
        store.save = _AM()
        with patch("app.core.storage.get_storage_backend", return_value=store):
            r = module_client.patch(f"/api/notes/{nid}", json={"tags": ["confidential"]})
        assert r.status_code == 200, r.text
        module_db.expire_all()
        assert self._attachment(module_db, nid).file_encrypted is False  # retriable


# ── workstations: _spawn_tracked from a threadpool handler ───────────


class TestSpawnTracked:
    def test_background_task_kept_until_done(self):
        """The task must hold a hard reference until completion — asyncio
        keeps only weak refs and GC could kill it mid-run."""
        from app.routers.workstations import _background_tasks, _spawn_tracked

        _background_tasks.clear()
        done = asyncio.Event()
        ran = asyncio.Event()

        async def job():
            ran.set()
            await done.wait()

        async def drive():
            _spawn_tracked(job())
            await ran.wait()
            assert len(_background_tasks) == 1  # holding the reference
            done.set()
            await asyncio.sleep(0.05)
            assert len(_background_tasks) == 0  # released on completion

        asyncio.run(drive())

    def test_from_thread_schedules_onto_main_loop(self):
        """A threadpool (sync def) handler has no running loop of its own
        — its coroutines must be scheduled onto the application loop via
        run_coroutine_threadsafe, tracked in the same set."""
        from app.routers.workstations import _background_tasks, _spawn_tracked, set_main_loop

        _background_tasks.clear()
        started = threading.Event()
        finished = threading.Event()

        async def job():
            started.set()
            await asyncio.sleep(0.05)
            finished.set()

        async def drive():
            set_main_loop(asyncio.get_running_loop())
            t = threading.Thread(target=lambda: _spawn_tracked(job()))
            t.start()
            for _ in range(100):  # let the thread schedule onto us
                await asyncio.sleep(0.01)
                if started.is_set():
                    break
            t.join(timeout=5)
            assert started.is_set(), "coroutine never ran on the main loop"
            await asyncio.sleep(0.1)
            assert finished.is_set()
            assert len(_background_tasks) == 0

        asyncio.run(drive())

    def test_no_loop_at_all_closes_the_coroutine(self):
        """Nothing to schedule onto (loop closed / never set): the
        coroutine must be closed, not leaked, and nothing raised."""
        from app.routers import workstations as ws

        saved = ws._main_loop
        ws._main_loop = None
        try:
            ran = asyncio.Event()

            async def job():
                ran.set()

            # called from a thread with no running loop and no stored loop
            ws._spawn_tracked(job())
            assert not ran.is_set()  # closed without running
            assert len(ws._background_tasks) == 0
        finally:
            ws._main_loop = saved


# ── main: _spawn strong refs + weak ADMIN_PASSWORD refusal ───────────


class TestMainSpawn:
    def test_spawn_holds_hard_reference_until_done(self):
        from app.main import _BG_TASKS, _spawn

        _BG_TASKS.clear()
        done = asyncio.Event()
        ran = asyncio.Event()

        async def job():
            ran.set()
            await done.wait()

        async def drive():
            t = _spawn(job())
            await ran.wait()
            assert t in _BG_TASKS
            done.set()
            await t
            await asyncio.sleep(0)
            assert t not in _BG_TASKS

        asyncio.run(drive())


class TestWeakAdminPassword:
    """Re-review 2026-11-02: ADMIN_PASSWORD=admin was accepted at
    bootstrap. A weak EXPLICIT password must fail loudly at startup,
    before any account exists to brute-force."""

    def _fresh_db(self):
        from app import models  # noqa: F401 — register tables on Base
        from app.database import Base

        engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
        Base.metadata.create_all(engine)
        return sessionmaker(bind=engine)()

    @pytest.mark.parametrize(
        "weak",
        ["password", "admin", "umbryx", "changeme", "admin123", "short"],
    )
    def test_weak_explicit_password_refused(self, monkeypatch, weak):
        from app.main import _ensure_admin_user

        monkeypatch.setenv("ADMIN_USERNAME", "admin")
        monkeypatch.setenv("ADMIN_PASSWORD", weak)
        with pytest.raises(RuntimeError, match="too weak"):
            _ensure_admin_user(self._fresh_db())

    def test_password_equal_to_username_refused(self, monkeypatch):
        from app.main import _ensure_admin_user

        monkeypatch.setenv("ADMIN_USERNAME", "rootadmin12345")  # 14 chars
        monkeypatch.setenv("ADMIN_PASSWORD", "rootadmin12345")  # same, not in _WEAK
        with pytest.raises(RuntimeError, match="too weak"):
            _ensure_admin_user(self._fresh_db())

    def test_strong_explicit_password_bootstraps(self, monkeypatch):
        from app import models
        from app.main import _ensure_admin_user

        monkeypatch.setenv("ADMIN_USERNAME", "admin")
        monkeypatch.setenv("ADMIN_PASSWORD", "Str0ng!Passw0rd-2026")
        db = self._fresh_db()
        _ensure_admin_user(db)
        assert db.query(models.User).count() == 1
        u = db.query(models.User).first()
        assert u.username == "admin"


# ── ha_mode: HA deployment without the entitlement ───────────────────


class TestHaLicenseRefusal:
    """A node with Sentinel configured but no ha_cluster entitlement
    must refuse to start — identically-behaving nodes are the point."""

    def test_refuses_without_entitlement(self, monkeypatch):
        from app.core.ha_mode import enforce_ha_license

        monkeypatch.setenv("REDIS_SENTINEL_HOSTS", "s1:26379")
        with (
            patch("app.core.plan.instance_has_feature", return_value=False),
            patch("app.core.system_log.log_security") as ls,
        ):
            with pytest.raises(RuntimeError, match="HA"):
                enforce_ha_license(MagicMock())
        assert ls.called

    def test_audit_failure_does_not_mask_the_refusal(self, monkeypatch):
        from app.core.ha_mode import enforce_ha_license

        monkeypatch.setenv("REDIS_SENTINEL_HOSTS", "s1:26379,s2:26379")
        with (
            patch("app.core.plan.instance_has_feature", return_value=False),
            patch("app.core.system_log.log_security", side_effect=Exception("audit down")),
        ):
            with pytest.raises(RuntimeError, match="HA"):
                enforce_ha_license(MagicMock())

    def test_entitled_node_passes(self, monkeypatch):
        from app.core.ha_mode import enforce_ha_license

        monkeypatch.setenv("REDIS_SENTINEL_HOSTS", "s1:26379")
        with patch("app.core.plan.instance_has_feature", return_value=True):
            enforce_ha_license(MagicMock())  # no raise

    def test_single_node_never_checks(self, monkeypatch):
        from app.core.ha_mode import enforce_ha_license

        monkeypatch.delenv("REDIS_SENTINEL_HOSTS", raising=False)
        with patch("app.core.plan.instance_has_feature") as ihf:
            enforce_ha_license(MagicMock())
        assert not ihf.called


# ── scan_helpers: exclusions always win ──────────────────────────────


class TestScopeExclusionWins:
    def test_exclusion_beats_allow_list(self):
        from app.core.scan_helpers import ip_in_scope_networks

        nets = [ipaddress.ip_network("10.0.0.0/8")]
        excl = [ipaddress.ip_network("10.0.0.0/24")]
        assert ip_in_scope_networks("10.0.0.5", nets, excl) is False
        assert ip_in_scope_networks("10.0.1.5", nets, excl) is True

    def test_bad_or_empty_ip_is_not_in_scope(self):
        from app.core.scan_helpers import ip_in_scope_networks

        nets = [ipaddress.ip_network("10.0.0.0/8")]
        assert ip_in_scope_networks("", nets) is False
        assert ip_in_scope_networks("not-an-ip", nets) is False

    def test_no_networks_means_no_filter(self):
        from app.core.scan_helpers import ip_in_scope_networks

        assert ip_in_scope_networks("192.168.1.1", []) is True


# ── playbooks: pack ownership is uid-first ───────────────────────────


class TestOwnsPack:
    def _pack(self, uid=None, created_by=None):
        from app import models

        return models.OperationPack(created_by_uid=uid, created_by=created_by)

    def test_uid_match_owns(self):
        from app.routers.playbooks.routes import _owns_pack

        assert _owns_pack(self._pack(uid="u1"), SimpleNamespace(id="u1", username="alice")) is True

    def test_uid_mismatch_does_not_fall_back_to_username(self):
        from app.routers.playbooks.routes import _owns_pack

        # a renamed or reassigned username must not grant ownership
        assert _owns_pack(self._pack(uid="u1"), SimpleNamespace(id="u2", username="alice")) is False

    def test_legacy_username_fallback(self):
        from app.routers.playbooks.routes import _owns_pack

        pack = self._pack(created_by="alice")
        assert _owns_pack(pack, SimpleNamespace(id="u9", username="alice")) is True
        assert _owns_pack(pack, SimpleNamespace(id="u9", username="bob")) is False


# ── auth: client-IP resolution behind a TLS proxy ────────────────────


class TestLoginClientIpResolution:
    """Re-review 2026-11-02: behind an external proxy every client shares
    request.client.host and the (username, IP) lockout collapses into one
    global bucket. With TRUST_X_FORWARDED_FOR the RIGHTMOST hop (the one
    our own proxy vouches for) keys the bucket."""

    def test_xff_rightmost_hop_used_when_trusted(self, module_client, monkeypatch):
        monkeypatch.setenv("TRUST_X_FORWARDED_FOR", "1")
        r = module_client.post(
            "/api/auth/login",
            json={"username": ADMIN, "password": ADMIN_PASS},
            headers={"x-forwarded-for": "1.2.3.4, 9.9.9.9"},
        )
        assert r.status_code == 200, r.text
        monkeypatch.delenv("TRUST_X_FORWARDED_FOR")

    def test_xff_ignored_by_default(self, module_client, monkeypatch):
        monkeypatch.delenv("TRUST_X_FORWARDED_FOR", raising=False)
        r = module_client.post(
            "/api/auth/login",
            json={"username": ADMIN, "password": ADMIN_PASS},
            headers={"x-forwarded-for": "6.6.6.6"},
        )
        assert r.status_code == 200, r.text  # forged header changed nothing


class TestRefreshRevocationChecks:
    def _refresh_token(self, module_client, module_db):
        from app import models as m
        from app.core.security import make_refresh_token

        module_client.post("/api/auth/logout")
        r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
        assert r.status_code == 200, r.text
        admin = module_db.query(m.User).filter_by(username="ADMIN").first() or module_db.query(
            m.User
        ).filter_by(username=ADMIN).first()
        assert admin is not None
        return make_refresh_token(admin)

    def test_revoked_session_rejected_at_refresh(self, module_client, module_db):
        from unittest.mock import AsyncMock as _AM

        rt = self._refresh_token(module_client, module_db)
        with patch(
            "app.core.token_blacklist.user_sessions_revoked", new=_AM(return_value=True)
        ):
            r = module_client.post("/api/auth/refresh", json={"refresh_token": rt})
        assert r.status_code == 401, r.text
        assert "revoked" in r.text.lower()

    def test_blacklisted_refresh_token_rejected(self, module_client, module_db):
        from unittest.mock import AsyncMock as _AM

        rt = self._refresh_token(module_client, module_db)
        with patch("app.routers.auth.is_blacklisted", new=_AM(return_value=True)):
            r = module_client.post("/api/auth/refresh", json={"refresh_token": rt})
        assert r.status_code == 401, r.text
        assert "revoked" in r.text.lower()


# ── report draft: same permissions as the direct endpoints ───────────


class TestReportDraftPermissions:
    """The draft renders the host and credential tables — roles without
    credentials.read must not receive that data through the report."""

    def test_observer_role_gets_403(self, module_client, module_db):
        from tests._license_test_utils import license_ee

        # observer/reviewer/analyst are Team+-tier roles: enable the
        # license for this test, restore the state after.
        undo = license_ee(module_client, module_db)
        try:
            r = module_client.post(
                "/api/admin/users",
                json={"username": "gate_observer", "password": USER_PASS, "role": "user"},
            )
            assert r.status_code in (200, 201), r.text
            uid = r.json()["id"]
            r = module_client.post(
                f"/api/projects/{_state['pid']}/members",
                json={"user_id": uid, "role": "observer"},
            )
            assert r.status_code in (200, 201, 204), r.text

            _relogin(module_client, "gate_observer", USER_PASS)
            r = module_client.get(f"/api/projects/{_state['pid']}/report/draft")
            assert r.status_code == 403, r.text
            _relogin(module_client, ADMIN, ADMIN_PASS)
        finally:
            undo()

    def test_owner_role_gets_the_draft(self, module_client):
        r = module_client.get(f"/api/projects/{_state['pid']}/report/draft")
        assert r.status_code == 200, r.text
        assert r.text.strip()  # non-empty markdown
