"""tool_guide + run_command AI tools — curated tool recipes for the agent."""

import asyncio
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.ai.tool_guides import TOOL_GUIDES, search_tool_guides
from app.core.ai.tool_registry import tool_registry


def _admin(client: TestClient):
    from tests.test_workstation_pool import _admin as _pool_admin

    return _pool_admin(client)


class TestToolGuideSearch:
    def test_zone_transfer_case_the_user_hit(self):
        # the exact failing scenario: "recon dns and zone transfer"
        m = search_tool_guides("dns zone transfer")
        topics = [g["topic"] for g in m]
        assert "dns-zone-transfer" in topics
        assert "dns-recon" in topics
        guide = next(g for g in m if g["topic"] == "dns-zone-transfer")
        assert any("AXFR" in c for c in guide["commands"])

    def test_aliases_rank_first(self):
        m = search_tool_guides("kerberos tickets spn")
        assert m[0]["topic"] == "kerberoast"

    def test_empty_and_garbage(self):
        assert search_tool_guides("") != []  # returns top entries
        assert search_tool_guides("zzzz-nonexistent-xyz") == []

    def test_placeholders_documented(self):
        for g in TOOL_GUIDES:
            assert g["commands"], g["topic"]
            assert g["aliases"]


class TestToolGuideTool:
    def test_registered_read_no_permission(self):
        td = tool_registry.get("tool_guide")
        assert td is not None
        assert td.risk.value == "read"
        assert td.required_permission is None

    def test_returns_matches(self, module_client: TestClient, module_db: Session):
        from app.core.ai_tools import tool_tool_guide

        r = tool_tool_guide(module_db, "p1", query="axfr")
        assert r["results"], r
        assert any("AXFR" in c for res in r["results"] for c in res["commands"])
        assert "placeholders" in r["hint"]


class TestRunCommandTool:
    def _pid(self, module_client: TestClient) -> str:
        _admin(module_client)
        r = module_client.post(
            "/api/projects",
            json={"name": "RunCmd tool", "added": "2026-09-26T00:00:00Z", "status": "active"},
        )
        return r.json()["id"]

    def test_registered_write_with_permission(self):
        td = tool_registry.get("run_command")
        assert td is not None
        assert td.risk.value == "write"
        assert td.required_permission == "command_outputs.create"
        assert "run_command" in {
            t["function"]["name"] for t in tool_registry.to_openai(include_critical=False)
        }

    def test_calls_exec_core_with_defaults(self, module_client: TestClient, module_db: Session):
        from app.core.ai_tools import tool_run_command

        pid = self._pid(module_client)
        with patch(
            "app.routers.attacker_exec.run_attacker_exec_core", new_callable=_FakeCore
        ) as core:
            r = asyncio.run(tool_run_command(module_db, pid, command="dig AXFR corp.local @10.0.0.1"))
        assert r["ok"] is True and r["exit_code"] == 0
        body = core.body
        assert body.command == "dig AXFR corp.local @10.0.0.1"
        assert body.activity_type == "recon"
        assert core.username == "ai"

    def test_safety_and_validation(self, module_client: TestClient, module_db: Session):
        from app.core.ai_tools import tool_run_command

        pid = self._pid(module_client)
        r1 = asyncio.run(tool_run_command(module_db, pid, command="  "))
        assert "required" in r1["error"]
        r2 = asyncio.run(tool_run_command(module_db, pid, command="rm -rf /"))
        assert "rejected" in r2["error"]


class _FakeCore:
    """Stands in for run_attacker_exec_core; records the call."""

    body = None
    username = None

    async def __call__(self, db, pid, body, username):
        _FakeCore.body = body
        _FakeCore.username = username
        return {
            "ok": True, "exit_code": 0, "stdout": "corp.local. 3600 IN SOA ...",
            "stderr": "", "job_id": "jobfake1", "activity": {},
        }


class TestAutoFallbackToGlobal:
    def test_auto_falls_back_to_global_without_project_attacker(self):
        """Auto mode + no project attacker host + a global target present ->
        global fallback instead of a 400 (the live run_command bug)."""
        from app.core.attacker_transport import resolve_exec_connection
        from unittest.mock import patch
        from fastapi import HTTPException
        from app.core import attacker_transport as at

        targets = [{"id": "g1", "host": "10.9.9.9", "port": 22, "username": "root", "enabled": True, "project_ids": []}]
        with patch.object(at, "resolve_project_attacker_host", side_effect=HTTPException(400, "No attacker host")), \
             patch.object(at, "list_attacker_targets_for_exec", return_value=targets), \
             patch.object(at, "list_global_targets_for_project", return_value=targets), \
             patch.object(at, "_resolve_global_ssh_auto", return_value=({"host": "10.9.9.9"}, [{"id": "g1"}])), \
             patch.object(at, "_ensure_attacker_host") as ensure:
            from app import models as _m
            ensure.return_value = _m.Host(pid="p1", ip="1.1.1.1", hostname="h", status="scanned")
            conn = resolve_exec_connection(object(), "p1", execution_mode="auto", host_id=None, cred_id=None, target_id=None, command_hint="")
        assert conn.ssh_config["host"] == "10.9.9.9"

    def test_project_mode_still_raises(self):
        from app.core.attacker_transport import _try_project_ssh
        from app.core import attacker_transport as at
        from fastapi import HTTPException
        from unittest.mock import patch

        with patch.object(at, "resolve_project_attacker_host", side_effect=HTTPException(400, "No attacker host")):
            try:
                _try_project_ssh(object(), "p1", "project", None, None)
                raise AssertionError("expected 400")
            except HTTPException as e:
                assert e.status_code == 400
