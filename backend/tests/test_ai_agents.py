"""AI agent personas — catalog seeding, tool allowlists, chat wiring."""

import pytest
from fastapi.testclient import TestClient

from app.core.ai.agents import get_agent, list_agents
from app.core.ai.tool_registry import tool_registry

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
_state: dict = {}


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    module_client.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
    assert r.status_code == 200
    yield


class TestCatalog:
    def test_builtin_agents_seeded(self, module_client, module_db):
        agents = list_agents(module_db)
        ids = {a["id"] for a in agents}
        assert {"field-op", "recon-analyst", "findings-drafter", "report-writer", "opsec-reviewer"} <= ids

    def test_readonly_agent_never_sees_write_tools(self, module_client, module_db):
        persona = get_agent(module_db, "opsec-reviewer")
        allowed = persona["allowed_tools"]
        schemas = tool_registry.to_openai(include_critical=False, allowed=allowed)
        names = {s["function"]["name"] for s in schemas}
        assert names == set(allowed)
        assert "create_finding" not in names
        assert "run_playbook" not in names

    def test_drafter_can_write_findings_not_playbooks(self, module_client, module_db):
        persona = get_agent(module_db, "findings-drafter")
        names = {
            s["function"]["name"]
            for s in tool_registry.to_openai(include_critical=False, allowed=persona["allowed_tools"])
        }
        assert "create_finding" in names
        assert "run_playbook" not in names, "critical tools stay out even for writers"

    def test_field_op_full_registry(self, module_client, module_db):
        persona = get_agent(module_db, "field-op")
        assert persona["allowed_tools"] is None
        full = tool_registry.to_openai(include_critical=False, allowed=None)
        assert len(full) == len(tool_registry.to_openai(include_critical=False))


class TestApi:
    def test_list_and_create_delete_custom(self, module_client, module_db):
        r = module_client.get("/api/ai/agents")
        assert r.status_code == 200
        before = len(r.json()["agents"])

        r = module_client.post(
            "/api/ai/agents",
            json={
                "name": "Loot Triage",
                "description": "sorts loot",
                "system_prompt": "You triage loot.",
                "allowed_tools": ["list_hosts"],
            },
        )
        assert r.status_code == 201, r.text
        agent = r.json()
        assert agent["builtin"] is False

        # cannot shadow a builtin id
        r = module_client.post(
            "/api/ai/agents",
            json={"name": "X", "system_prompt": "x", "id": "field-op"},
        )
        assert r.status_code == 201
        assert r.json()["id"] != "field-op"
        module_client.delete(f"/api/ai/agents/{r.json()['id']}")

        r = module_client.delete(f"/api/ai/agents/{agent['id']}")
        assert r.status_code == 204
        # builtin is protected
        r = module_client.delete("/api/ai/agents/field-op")
        assert r.status_code == 404
        assert len(module_client.get("/api/ai/agents").json()["agents"]) == before


class TestChatWiring:
    def test_chat_with_agent_and_unknown_404(self, module_client, module_db):
        r = module_client.post(
            "/api/projects", json={"name": f"AiAg{__import__('app.core.utils', fromlist=['new_id']).new_id('a')[:6]}",
                                   "added": "2025-01-01T00:00:00Z"}
        )
        pid = r.json()["id"]
        _state["pid"] = pid

        r = module_client.post(
            f"/api/projects/{pid}/ai/chats", json={"agent_id": "recon-analyst"}
        )
        assert r.status_code == 200, r.text  # historical contract: 200, not 201
        chat = r.json()
        assert chat["agent_id"] == "recon-analyst"
        assert chat["title"] == "Recon Analyst"
        _state["cid"] = chat["id"]

        r = module_client.post(f"/api/projects/{pid}/ai/chats", json={"agent_id": "no-such"})
        assert r.status_code == 404

    def test_history_uses_persona_prompt(self, module_client, module_db):
        from app.core.ai.agents import get_agent
        from app.models import AIChat
        from app.routers.ai_v2 import _load_history

        history = _load_history(module_db, _state["cid"], "hello", _state["pid"])
        system = next(m for m in history if getattr(m, "role", None) == "system")
        persona = get_agent(module_db, "recon-analyst")
        assert persona["system_prompt"].split("\n")[0] in system.content
        assert "hosts" in system.content, "project stats remain appended"

    def test_chat_allowed_tools_helper(self, module_client, module_db):
        from app.models import AIChat
        from app.routers.ai_v2 import _chat_allowed_tools

        chat = module_db.query(AIChat).get(_state["cid"])
        allowed = _chat_allowed_tools(module_db, chat)
        assert "create_finding" not in allowed
        assert "list_hosts" in allowed

        plain = module_client.post(f"/api/projects/{_state['pid']}/ai/chats", json={}).json()
        assert _chat_allowed_tools(module_db, module_db.query(AIChat).get(plain["id"])) is None
