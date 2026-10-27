"""
Startup migration retry loop (app/main.py _run_migrations).

Found live on an update-script deployment: the backend container can
start while PostgreSQL is still in WAL recovery — the compose
healthcheck passes (socket is up) but every query gets
'FATAL: the database system is starting up'. Migrations used to crash
the process instantly, Docker restarted it into the same race, and
jobs orphaned on every cycle. The retry loop fixed it; these tests pin
its three behaviours: retry-then-succeed on readiness errors, fail
fast on real migration errors, and give up after 30 attempts.
"""

import pytest

from app.main import _run_migrations


class _FakeURL:
    def render_as_string(self, hide_password=False):
        return "sqlite://"


class _FakeEngine:
    url = _FakeURL()


def _patch_alembic(monkeypatch, upgrades):
    """Point _run_migrations' alembic machinery at a fake upgrade and a
    recording sleep. `upgrades` is the sequence of outcomes: Exception
    instances raise, anything else succeeds. Returns the sleep log."""
    import alembic.command as real_command
    import time as time_mod

    import app.main as main_mod

    monkeypatch.setattr(main_mod, "engine", _FakeEngine(), raising=True)

    calls = {"n": 0}

    def fake_upgrade(cfg, target):
        idx = min(calls["n"], len(upgrades) - 1)
        calls["n"] += 1
        outcome = upgrades[idx]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    monkeypatch.setattr(real_command, "upgrade", fake_upgrade, raising=True)

    recorded = []

    def fake_sleep(sec):
        recorded.append(sec)

    monkeypatch.setattr(time_mod, "sleep", fake_sleep, raising=True)
    return recorded


class TestRunMigrationsRetry:
    def test_retries_then_succeeds_on_db_starting_up(self, monkeypatch, capsys):
        from sqlalchemy.exc import OperationalError

        err = OperationalError(
            "stmt",
            {},
            Exception("connection to server failed: FATAL: the database system is starting up"),
        )
        sleeps = _patch_alembic(monkeypatch, [err, err, "ok"])
        _run_migrations()
        assert len(sleeps) == 2
        assert all(s == 2 for s in sleeps)
        out = capsys.readouterr().out
        assert "[startup] DB not ready (attempt 1/30)" in out
        assert "[startup] DB not ready (attempt 2/30)" in out

    def test_retries_on_connection_refused(self, monkeypatch, capsys):
        from sqlalchemy.exc import OperationalError

        err = OperationalError("stmt", {}, Exception("connection refused"))
        sleeps = _patch_alembic(monkeypatch, [err, "ok"])
        _run_migrations()
        assert len(sleeps) == 1

    def test_real_migration_error_raises_immediately(self, monkeypatch, capsys):
        err = ValueError("duplicate column: hosts.fqdn")
        sleeps = _patch_alembic(monkeypatch, [err, "ok"])
        with pytest.raises(ValueError, match="duplicate column"):
            _run_migrations()
        assert sleeps == []  # no retry for non-readiness errors
        assert "DB not ready" not in capsys.readouterr().out

    def test_gives_up_after_30_attempts(self, monkeypatch):
        from sqlalchemy.exc import OperationalError

        err = OperationalError("stmt", {}, Exception("FATAL: the database system is starting up"))
        sleeps = _patch_alembic(monkeypatch, [err])  # always raises
        with pytest.raises(OperationalError, match="starting up"):
            _run_migrations()
        # 30 attempts → 29 sleeps between them
        assert len(sleeps) == 29
