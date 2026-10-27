"""AI agent run_scan tool — agentic scan execution (2026-09-26).

The chat agent had read-only tools; asking it to actually scan made the
model hallucinate results and then confess it had no tools. run_scan
queues a real scan Job through the standard pipeline and hands the agent
a job_id to poll.
"""

from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.ai.tool_registry import tool_registry


def _admin(client: TestClient):
    from tests.test_workstation_pool import _admin as _pool_admin

    return _pool_admin(client)


class TestRunScanTool:
    def _pid(self, module_client: TestClient) -> str:
        _admin(module_client)
        r = module_client.post(
            "/api/projects",
            json={"name": "AI scan tool", "added": "2026-09-26T00:00:00Z", "status": "active"},
        )
        return r.json()["id"]

    def test_registered_and_visible_to_model(self):
        td = tool_registry.get("run_scan")
        assert td is not None
        names = {t["function"]["name"] for t in tool_registry.to_openai(include_critical=False)}
        assert "run_scan" in names  # WRITE risk — the model sees it
        assert td.required_permission == "command_outputs.create"

    def test_queues_job_and_returns_job_id(self, module_client: TestClient, module_db: Session):
        from app import models
        from app.core.ai_tools import tool_run_scan

        pid = self._pid(module_client)
        with patch("app.core.job_tracker.queue_job") as qj, patch(
            "app.core.job_runner.schedule_job_run"
        ) as sched:
            job_row = models.Job(
                id="jobtestscan1", pid=pid, type="nmap", status="queued",
                title="[AI] nmap scan", target="10.0.0.0/24",
            )
            qj.return_value = job_row
            r = tool_run_scan(module_db, pid, tool="Nmap", target="10.0.0.0/24", flags="-sV")
        assert r.get("job_id") == "jobtestscan1", r
        assert r["status"] == "queued"
        assert "get_job_output" in r["message"]
        # queued through the standard pipeline
        _, kwargs = qj.call_args
        assert kwargs["connector_key"] == "nmap" and kwargs["operation"] == "scan"
        assert kwargs["request_json"]["target"] == "10.0.0.0/24"
        assert kwargs["request_json"]["flags"] == "-sV"
        sched.assert_called_once_with("jobtestscan1", pid=pid)

    def test_validation(self, module_client: TestClient, module_db: Session):
        from app.core.ai_tools import tool_run_scan

        pid = self._pid(module_client)
        r1 = tool_run_scan(module_db, pid, tool="sqlmap", target="10.0.0.1")
        assert "unsupported scan tool" in r1["error"]
        r2 = tool_run_scan(module_db, pid, tool="nmap", target="   ")
        assert "target is required" in r2["error"]

    def test_rbac_viewer_denied(self, module_client: TestClient, module_db: Session):
        """run_scan requires command_outputs.create — read-only roles must not
        execute it through the chat."""
        from fastapi import HTTPException

        from app import models
        from app.core.access import check_pid_access

        pid = self._pid(module_client)
        viewer = models.User(role="user")
        try:
            check_pid_access(module_db, pid, viewer, "command_outputs.create")
            raise AssertionError("expected 403")
        except HTTPException as e:
            assert e.status_code in (403, 404)
        assert viewer.role != "platform_admin"
