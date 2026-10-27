"""termtrack PTY installer: shell-aware target choice and honest verification.

The installer runs a shell script over the workstation's management
channel; these tests mock the channel and assert the three behaviours
that were broken live (root-only target, false transport-success,
zsh-hostile syntax):
  - profile.d works (root exec) → installed → /etc/profile.d/...
  - profile.d unwritable → falls back to the rc of $SHELL (zsh/bash)
  - marker never reads back → reported as failure, no pty_enabled
"""

import pytest

from app.core.termtrack import pty as pty_mod


def _run_channel_spy(stdout: str):
    calls = {"script": None}

    def fake_run_channel(db, ws, script, timeout=25):
        calls["script"] = script
        return stdout

    return fake_run_channel, calls


def _ws(db):
    """Real row: install stores pty_install_target via flag_modified."""
    from app.core.utils import new_id, ts_now
    from app.models import OperatorWorkstation

    ws = OperatorWorkstation(
        id=new_id("ws"), name="pty-test-ws", status="ready",
        access_address="10.0.0.1", created_at=ts_now(), is_pool=True, provider="manual",
    )
    db.add(ws)
    db.commit()
    return ws


@pytest.fixture()
def _ssh_channel(monkeypatch):
    """Force the SSH branch with a canned run_ssh_command result."""

    def install(stdout: str, exit_code: int = 0, ok: bool = True):
        result = {"ok": ok, "stdout": stdout, "stderr": "", "exit_code": exit_code}

        def fake_exec_channel(db, ws):
            return (["__ssh__"], None)

        def fake_ssh(cfg, script, timeout):
            result["script"] = script
            return result

        def fake_cfg(ws, db):
            return {"host": "h", "username": "u", "private_key": "k"}

        monkeypatch.setattr(pty_mod, "_exec_channel", fake_exec_channel, raising=False)
        import app.core.workstation.pool as pool_mod

        monkeypatch.setattr(pool_mod, "_ssh_config_for", fake_cfg, raising=True)
        import app.core.ssh_exec as ssh_mod

        monkeypatch.setattr(ssh_mod, "run_ssh_command", fake_ssh, raising=True)
        return result

    return install


class TestInstallPtyRecorder:
    def test_profile_d_success(self, db, _ssh_channel):
        _ssh_channel("installed:/etc/profile.d/umbryx-termtrack.sh\n")
        ws = _ws(db)
        ok, reason = pty_mod.install_pty_recorder(db, ws)
        assert ok is True
        assert "/etc/profile.d" in reason
        assert ws.meta["pty_install_target"] == "/etc/profile.d/umbryx-termtrack.sh"

    def test_falls_back_to_user_shell_rc(self, db, _ssh_channel):
        # profile.d write fails → the script picks the rc by $SHELL (zsh)
        _ssh_channel("installed:/home/administrator/.zshrc\n")
        ws = _ws(db)
        ok, reason = pty_mod.install_pty_recorder(db, ws)
        assert ok is True
        assert ".zshrc" in reason

    def test_failed_write_is_failure_not_transport_success(self, db, _ssh_channel):
        # the marker never read back — old code reported success from the
        # transport alone; now the missing `installed:` prefix fails it
        _ssh_channel("failed:/etc/profile.d/umbryx-termtrack.sh\n", exit_code=1)
        ws = _ws(db)
        ok, reason = pty_mod.install_pty_recorder(db, ws)
        assert ok is False
        assert "failed" in reason

    def test_nonzero_exit_is_failure(self, db, _ssh_channel):
        _ssh_channel("installed:/etc/profile.d/umbryx-termtrack.sh\n", exit_code=2)
        ok, _ = pty_mod.install_pty_recorder(db, _ws(db))
        assert ok is False

    def test_script_is_posix_clean(self, db, _ssh_channel):
        result = _ssh_channel("installed:/etc/profile.d/umbryx-termtrack.sh\n")
        pty_mod.install_pty_recorder(db, _ws(db))
        script = result["script"]
        # zsh-hostile constructs that broke the live install
        assert " || { " not in script and "esac" not in script
        # base64 transport + marker verification present
        assert "base64 -d" in script and "grep -q" in script
