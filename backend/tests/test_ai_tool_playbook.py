"""Tool playbook in the agent system prompt (2026-09-26)."""

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.ai.tool_playbook import build_tool_playbook
from app.core.ai.tool_registry import tool_registry


def _admin(client: TestClient):
    from tests.test_workstation_pool import _admin as _pool_admin

    return _pool_admin(client)


class TestToolPlaybook:
    def test_sections_follow_available_tools(self):
        all_tools = set(tool_registry.list_names())
        pb_all = build_tool_playbook(all_tools)
        # full registry → all sections present
        assert "SCANNING (async!)" in pb_all
        assert "RECON WORKFLOW" in pb_all
        assert "TOOL DISCIPLINE" in pb_all
        # empty registry → discipline + style only, no tool-specific sections
        pb_empty = build_tool_playbook(set())
        assert "TOOL DISCIPLINE" in pb_empty
        assert "SCANNING" not in pb_empty
        assert "RECON WORKFLOW" not in pb_empty

    def test_core_rules_present(self):
        pb = build_tool_playbook(set(tool_registry.list_names()))
        assert "Never invent project data" in pb
        assert "receipt, not a result" in pb  # async scan discipline
        assert "get_scope" in pb

    def test_system_prompt_includes_playbook(self, module_client: TestClient, module_db: Session):
        from app.routers.ai_v2 import _build_system_prompt

        _admin(module_client)
        r = module_client.post(
            "/api/projects",
            json={"name": "Playbook prompt", "added": "2026-09-26T00:00:00Z", "status": "active"},
        )
        assert r.status_code in (200, 201), r.text
        pid = r.json()["id"]
        prompt = _build_system_prompt(module_db, pid)
        assert "TOOL DISCIPLINE" in prompt
        assert "Never invent project data" in prompt

        # persona (custom) prompt path keeps mission + stats + playbook
        custom = _build_system_prompt(module_db, pid, custom_prompt="You are the Recon Analyst.")
        assert custom.startswith("You are the Recon Analyst.")
        assert "TOOL DISCIPLINE" in custom
