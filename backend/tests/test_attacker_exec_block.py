"""attacker-exec: the HostActivity must close when the ROE guard blocks the job.

Found live: blocked commands (out-of-scope target in the command) left a
ghost 'running' activity forever — the guard fires after the activity row
is already committed. Unit level: mock the transport resolution and force
start_job to raise EngagementViolation; the activity must land 'blocked'.
"""

import pytest

from app import models
from app.core.utils import new_id, ts_now


@pytest.fixture()
def _project(db):
    from app.models import Project

    pid = new_id("p")
    db.add(Project(id=pid, name="roe-block", status="active", added=ts_now()))
    db.commit()
    return pid


def _attacker_host(db, pid):
    host = models.Host(
        id=new_id("hst"), pid=pid, ip="203.0.113.10", hostname="atk", os="",
        status="attacker", ports=[], services=[], tags=[], role="attacker",
        is_attacker=True,
    )
    db.add(host)
    db.commit()
    return host


class TestBlockedClosesActivity:
    def test_guard_block_closes_activity(self, db, _project, monkeypatch):
        from unittest.mock import MagicMock

        from app.core.roe_guard import EngagementViolation
        from app.plugins.registry import registry as plugin_registry
        from app.routers.attacker_exec import AttackerExecBody, run_attacker_exec_core

        # модуль attacker_ssh включён (как в проде)
        fake_mod = MagicMock()
        fake_mod.enabled = True
        monkeypatch.setattr(plugin_registry, "get", lambda name: fake_mod if name == "attacker_ssh" else None)

        host = _attacker_host(db, _project)

        # контекст исполнения: без SSH-транспорта — падаем ДО старта job
        from app.routers import attacker_exec as ae

        monkeypatch.setattr(
            ae, "_resolve_execution_context",
            lambda d, p, b: (None, [], False, host, None),
        )

        def boom(*a, **k):
            raise EngagementViolation("out of scope")

        monkeypatch.setattr(ae, "start_job", boom)

        body = AttackerExecBody(command="nmap 203.0.113.99", timeout_seconds=30)
        with pytest.raises(EngagementViolation):
            import asyncio

            asyncio.run(run_attacker_exec_core(db, _project, body, "admin"))

        acts = db.query(models.HostActivity).filter_by(pid=_project).all()
        assert acts, "активность должна быть создана"
        assert acts[-1].status == "blocked"
        assert "ROE" in (acts[-1].summary or "") or "Blocked" in (acts[-1].summary or "")
