import asyncio

"""AI action attribution — agent-made entities are labeled ai:<username>."""

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session


def _admin(client: TestClient):
    from tests.test_workstation_pool import _admin as _pool_admin

    return _pool_admin(client)


class TestActorLabelInjection:
    def _pid(self, module_client: TestClient) -> str:
        _admin(module_client)
        r = module_client.post(
            "/api/projects",
            json={"name": "AI attribution", "added": "2026-09-26T00:00:00Z", "status": "active"},
        )
        return r.json()["id"]

    def test_run_scan_created_by_ai_user(self, module_client: TestClient, module_db: Session):
        from unittest.mock import patch

        from app import models
        from app.core.ai.tool_registry import tool_registry

        pid = self._pid(module_client)
        admin_uid = (
            module_db.query(models.User).filter(models.User.username == "admin").first().id
        )
        with patch("app.core.job_tracker.queue_job") as qj, patch(
            "app.core.job_runner.schedule_job_run"
        ):
            qj.return_value = models.Job(
                id="jobaiattr1", pid=pid, type="nmap", status="queued",
                title="[AI] nmap scan", target="10.0.0.1",
            )
            r = asyncio.run(tool_registry.execute(
                module_db, pid, "run_scan",
                {"tool": "nmap", "target": "10.0.0.1"},
                user_id=admin_uid,
            ))
        assert r.get("job_id") == "jobaiattr1"
        _, kwargs = qj.call_args
        assert kwargs["created_by"] == "ai:admin"

    def test_create_finding_source_ai_user(self, module_client: TestClient, module_db: Session):
        from app import models
        from app.core.ai.tool_registry import tool_registry

        pid = self._pid(module_client)
        admin_uid = (
            module_db.query(models.User).filter(models.User.username == "admin").first().id
        )
        r = asyncio.run(tool_registry.execute(
            module_db, pid, "create_finding",
            {"title": "AI found something", "severity": "medium", "description": "x"},
            user_id=admin_uid,
        ))
        assert "error" not in r
        finding = module_db.query(models.Finding).filter(models.Finding.id == r["id"]).first()
        assert finding.source == "ai:admin"

    def test_create_note_tagged_ai_user(self, module_client: TestClient, module_db: Session):
        from app import models
        from app.core.ai.tool_registry import tool_registry

        pid = self._pid(module_client)
        admin_uid = (
            module_db.query(models.User).filter(models.User.username == "admin").first().id
        )
        r = asyncio.run(tool_registry.execute(
            module_db, pid, "create_note",
            {"title": "agent note", "content": "made by the agent", "tags": ["recon"]},
            user_id=admin_uid,
        ))
        note = module_db.query(models.Note).filter(models.Note.id == r["id"]).first()
        assert "ai:admin" in (note.tags or [])
        assert "recon" in (note.tags or [])

    def test_automation_path_gets_generic_label(self, module_client: TestClient, module_db: Session):
        """Automations call execute() without user_id — labeled ai:automation."""
        from unittest.mock import patch

        from app import models
        from app.core.ai.tool_registry import tool_registry

        pid = self._pid(module_client)
        with patch("app.core.job_tracker.queue_job") as qj, patch(
            "app.core.job_runner.schedule_job_run"
        ):
            qj.return_value = models.Job(
                id="jobauto1", pid=pid, type="nmap", status="queued",
                title="[AI] nmap scan", target="10.0.0.2",
            )
            asyncio.run(tool_registry.execute(
                module_db, pid, "run_scan", {"tool": "nmap", "target": "10.0.0.2"}
            ))
        _, kwargs = qj.call_args
        assert kwargs["created_by"] == "ai:automation"

    def test_actor_label_not_exposed_to_model(self):
        from app.core.ai.tool_registry import tool_registry

        for t in tool_registry.to_openai(include_critical=False):
            props = t["function"]["parameters"]["properties"]
            assert "actor_label" not in props and "user_id" not in props
