"""
Unit tests for the AI integration module.

Tests:
  - Provider registry (register, get, list, schema)
  - Provider adapter format conversion (messages, tools, response parsing)
  - Tool registry (register, execute, risk classification)
  - Credential store (encrypt/decrypt, mask, CRUD)
  - Agent engine (mock LLM, tool execution, confirmation flow)
  - Chat persistence (models, serialization)
"""

import asyncio
import json
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from datetime import datetime, timezone

from app.core.ai.provider import (
    AIProviderRegistry,
    AIProvider,
    ChatMessage,
    ChatResponse,
    ToolCall,
    CredentialField,
    ProviderInfo,
)
from app.core.ai.tool_registry import ToolRegistry, ToolDef, RiskLevel, tool_registry
from app.core.ai.credential_store import CredentialStore
from app.core.ai.agent import AgentEngine, AgentResult


# ── Provider Registry Tests ───────────────────────────────────────────


class TestProviderRegistry:
    def test_builtin_providers_loaded(self):
        types = AIProviderRegistry.list_types()
        assert "openai" in types
        assert "anthropic" in types
        assert "ollama" in types

    def test_get_provider_instance(self):
        p = AIProviderRegistry.get("openai")
        assert p is not None
        assert p.get_type() == "openai"
        assert p.get_display_name() == "OpenAI"

    def test_get_unknown_provider(self):
        assert AIProviderRegistry.get("nonexistent") is None

    def test_list_infos(self):
        infos = AIProviderRegistry.list_infos()
        assert len(infos) >= 3
        openai_info = [i for i in infos if i.type == "openai"][0]
        assert openai_info.category == "cloud"
        assert openai_info.supports_tools is True
        assert len(openai_info.credentials_schema) > 0

    def test_get_schema(self):
        schema = AIProviderRegistry.get_schema("anthropic")
        assert len(schema) >= 1
        assert any(f["name"] == "api_key" for f in schema)

    def test_has(self):
        assert AIProviderRegistry.has("openai") is True
        assert AIProviderRegistry.has("nonexistent") is False

    def test_singleton_instances(self):
        p1 = AIProviderRegistry.get("openai")
        p2 = AIProviderRegistry.get("openai")
        assert p1 is p2


# ── ChatMessage / ToolCall Dataclass Tests ────────────────────────────


class TestChatMessage:
    def test_to_openai_dict_simple(self):
        msg = ChatMessage(role="user", content="Hello")
        d = msg.to_openai_dict()
        assert d["role"] == "user"
        assert d["content"] == "Hello"

    def test_to_openai_dict_with_tool_calls(self):
        tc = ToolCall(id="call_1", name="list_hosts", arguments={"query": "10.0.0.1"})
        msg = ChatMessage(role="assistant", content="", tool_calls=[tc])
        d = msg.to_openai_dict()
        assert "tool_calls" in d
        assert d["tool_calls"][0]["function"]["name"] == "list_hosts"

    def test_tool_call_id_in_dict(self):
        msg = ChatMessage(role="tool", content="result", tool_call_id="call_1", name="list_hosts")
        d = msg.to_openai_dict()
        assert d["tool_call_id"] == "call_1"
        assert d["name"] == "list_hosts"


# ── Tool Registry Tests ───────────────────────────────────────────────


class TestToolRegistry:
    def test_builtin_tools_loaded(self):
        names = tool_registry.list_names()
        assert "list_hosts" in names
        assert "create_finding" in names
        assert "run_playbook" in names
        assert len(names) >= 12

    def test_tool_risk_levels(self):
        assert tool_registry.get("list_hosts").risk == RiskLevel.READ
        assert tool_registry.get("create_finding").risk == RiskLevel.WRITE
        assert tool_registry.get("run_playbook").risk == RiskLevel.CRITICAL

    def test_tool_def_to_openai(self):
        td = tool_registry.get("list_hosts")
        d = td.to_openai()
        assert d["type"] == "function"
        assert d["function"]["name"] == "list_hosts"
        assert "properties" in d["function"]["parameters"]

    def test_tool_def_to_anthropic(self):
        td = tool_registry.get("list_hosts")
        d = td.to_anthropic()
        assert d["name"] == "list_hosts"
        assert "input_schema" in d

    def test_tool_def_to_dict(self):
        td = tool_registry.get("create_finding")
        d = td.to_dict()
        assert d["risk"] == "write"
        assert "title" in d["required"]
        assert "severity" in d["required"]

    def test_to_openai_excludes_critical(self):
        tools = tool_registry.to_openai(include_critical=False)
        names = [t["function"]["name"] for t in tools]
        assert "run_playbook" not in names
        assert "list_hosts" in names

    def test_to_openai_includes_critical(self):
        tools = tool_registry.to_openai(include_critical=True)
        names = [t["function"]["name"] for t in tools]
        assert "run_playbook" in names

    @pytest.mark.asyncio
    async def test_execute_unknown_tool(self):
        result = await tool_registry.execute(MagicMock(), "p1", "nonexistent", {})
        assert "error" in result

    @pytest.mark.asyncio
    async def test_execute_tool_with_error(self):
        mock_db = MagicMock()
        mock_db.query.side_effect = Exception("DB error")
        result = await tool_registry.execute(mock_db, "p1", "list_hosts", {})
        assert "error" in result

    def test_custom_registry_register_and_unregister(self):
        reg = ToolRegistry()

        @reg.register("custom_tool", "A custom tool", risk=RiskLevel.READ, params={}, required=[])
        def custom_tool(db, pid):
            return {"ok": True}

        assert reg.get("custom_tool") is not None
        assert "custom_tool" in reg.list_names()
        assert reg.unregister("custom_tool") is True
        assert reg.get("custom_tool") is None


# ── Credential Store Tests ────────────────────────────────────────────


class TestCredentialStore:
    def _mock_db(self, stored=None):
        db = MagicMock()
        row = MagicMock()
        row.value = stored or {}
        db.query.return_value.filter.return_value.first.return_value = row
        return db

    def test_get_config_defaults(self):
        db = self._mock_db({})
        store = CredentialStore(db)
        cfg = store.get_config()
        assert cfg["ai_enabled"] is True
        assert cfg["agent_mode"] is True
        assert cfg["max_tool_calls"] == 10
        assert cfg["require_confirmation_writes"] is True
        assert cfg["block_critical_tools"] is True
        assert cfg["providers"] == []

    def test_add_and_mask_provider(self):
        db = self._mock_db({})
        store = CredentialStore(db)
        result = store.add_provider({
            "id": "test1",
            "name": "Test",
            "provider": "openai",
            "model": "gpt-4o",
            "api_key": "sk-abcdefghij",
        })
        assert result["api_key"].startswith("****")
        assert "sk-" not in result["api_key"]

    def test_get_provider_decrypted(self):
        db = self._mock_db({})
        store = CredentialStore(db)
        store.add_provider({
            "id": "test2",
            "provider": "openai",
            "api_key": "sk-secret123",
        })
        decrypted = store.get_provider("test2", decrypt=True)
        assert decrypted["api_key"] == "sk-secret123"

    def test_get_provider_masked(self):
        db = self._mock_db({})
        store = CredentialStore(db)
        store.add_provider({
            "id": "test3",
            "provider": "openai",
            "api_key": "sk-secret123",
        })
        masked = store.get_provider("test3", decrypt=False)
        assert masked["api_key"].startswith("****")

    def test_update_provider_preserves_key(self):
        db = self._mock_db({})
        store = CredentialStore(db)
        store.add_provider({
            "id": "test4",
            "provider": "openai",
            "api_key": "sk-original",
        })
        store.update_provider("test4", {"model": "gpt-4o-mini"})
        decrypted = store.get_provider("test4", decrypt=True)
        assert decrypted["api_key"] == "sk-original"
        assert decrypted["model"] == "gpt-4o-mini"

    def test_update_provider_changes_key(self):
        db = self._mock_db({})
        store = CredentialStore(db)
        store.add_provider({
            "id": "test5",
            "provider": "openai",
            "api_key": "sk-old",
        })
        store.update_provider("test5", {"api_key": "sk-new"})
        decrypted = store.get_provider("test5", decrypt=True)
        assert decrypted["api_key"] == "sk-new"

    def test_remove_provider(self):
        db = self._mock_db({})
        store = CredentialStore(db)
        store.add_provider({"id": "test6", "provider": "openai", "api_key": "k"})
        assert store.remove_provider("test6") is True
        assert store.get_provider("test6") is None

    def test_get_next_provider_priority(self):
        db = self._mock_db({})
        store = CredentialStore(db)
        store.add_provider({"id": "low", "provider": "openai", "api_key": "k", "enabled": True, "priority": 10})
        store.add_provider({"id": "high", "provider": "openai", "api_key": "k", "enabled": True, "priority": 1})
        next_p = store.get_next_provider()
        assert next_p["id"] == "high"

    def test_get_next_provider_skip_disabled(self):
        db = self._mock_db({})
        store = CredentialStore(db)
        store.add_provider({"id": "disabled", "provider": "openai", "api_key": "k", "enabled": False, "priority": 1})
        store.add_provider({"id": "enabled", "provider": "openai", "api_key": "k", "enabled": True, "priority": 10})
        next_p = store.get_next_provider()
        assert next_p["id"] == "enabled"

    def test_get_next_provider_skip_ids(self):
        db = self._mock_db({})
        store = CredentialStore(db)
        store.add_provider({"id": "p1", "provider": "openai", "api_key": "k", "enabled": True, "priority": 1})
        store.add_provider({"id": "p2", "provider": "openai", "api_key": "k", "enabled": True, "priority": 2})
        next_p = store.get_next_provider(skip_ids={"p1"})
        assert next_p["id"] == "p2"

    def test_encryption_at_rest(self):
        from app.core.crypto import is_encrypted
        db = self._mock_db({})
        store = CredentialStore(db)
        store._save = MagicMock()
        store._load = MagicMock(return_value={"providers": []})
        store.add_provider({"id": "enc1", "provider": "openai", "api_key": "sk-test123"})
        saved_cfg = store._save.call_args[0][0]
        key = saved_cfg["providers"][0]["api_key"]
        assert is_encrypted(key)

    def test_get_provider_types(self):
        types = CredentialStore.get_provider_types()
        assert len(types) >= 3
        assert any(t["type"] == "openai" for t in types)


# ── Agent Engine Tests (mocked) ───────────────────────────────────────


class TestAgentEngine:
    def _mock_config(self):
        return {
            "ai_enabled": True,
            "agent_mode": True,
            "max_tool_calls": 5,
            "require_confirmation_writes": True,
            "block_critical_tools": True,
            "providers": [],
        }

    @pytest.mark.asyncio
    async def test_no_providers_configured(self):
        from app.core.ai.agent import AgentEngine, AgentResult

        mock_db = MagicMock()
        with patch("app.core.ai.agent.CredentialStore") as MockStore:
            store = MockStore.return_value
            store.get_config.return_value = self._mock_config()
            store.get_next_provider.return_value = None
            engine = AgentEngine(mock_db)
            result = await engine.run(messages=[], pid="p1")
            assert isinstance(result, AgentResult)
            assert "No AI providers" in result.content

    @pytest.mark.asyncio
    async def test_simple_response_no_tool_calls(self):
        from app.core.ai.agent import AgentEngine

        mock_db = MagicMock()
        with patch("app.core.ai.agent.CredentialStore") as MockStore, \
             patch("app.core.ai.agent.AIProviderRegistry") as MockReg:

            store = MockStore.return_value
            store.get_config.return_value = self._mock_config()
            store.get_next_provider.return_value = {
                "id": "p1", "provider": "openai", "api_key": "k", "base_url": "", "model": "gpt-4o",
            }

            mock_provider = AsyncMock()
            mock_provider.chat.return_value = ChatResponse(
                content="Hello! How can I help?",
                tool_calls=None,
                provider_id="p1",
                model="gpt-4o",
            )
            MockReg.get.return_value = mock_provider

            engine = AgentEngine(mock_db)
            result = await engine.run(
                messages=[ChatMessage(role="user", content="Hi")],
                pid="p1",
                agent_mode=True,
            )
            assert "Hello" in result.content
            assert result.tool_calls_made == 0

    @pytest.mark.asyncio
    async def test_critical_tool_blocked(self):
        from app.core.ai.agent import AgentEngine
        from app.core.ai.tool_registry import RiskLevel

        mock_db = MagicMock()
        with patch("app.core.ai.agent.CredentialStore") as MockStore, \
             patch("app.core.ai.agent.AIProviderRegistry") as MockReg:

            store = MockStore.return_value
            store.get_config.return_value = self._mock_config()
            store.get_next_provider.return_value = {
                "id": "p1", "provider": "openai", "api_key": "k", "base_url": "", "model": "gpt-4o",
            }

            mock_provider = AsyncMock()

            call_count = [0]

            async def mock_chat(**kwargs):
                call_count[0] += 1
                if call_count[0] == 1:
                    return ChatResponse(
                        content="",
                        tool_calls=[ToolCall(id="c1", name="run_playbook", arguments={"playbook_id": "x"})],
                        provider_id="p1",
                    )
                return ChatResponse(content="Tool was blocked", provider_id="p1")

            mock_provider.chat = mock_chat
            MockReg.get.return_value = mock_provider

            engine = AgentEngine(mock_db)
            result = await engine.run(
                messages=[ChatMessage(role="user", content="run a playbook")],
                pid="p1",
                agent_mode=True,
            )
            blocked_steps = [s for s in result.steps if s.type == "tool_result" and s.tool_name == "run_playbook"]
            assert len(blocked_steps) >= 1
            assert "blocked" in blocked_steps[0].tool_result.get("error", "").lower()

    @pytest.mark.asyncio
    async def test_write_tool_requires_confirmation(self):
        from app.core.ai.agent import AgentEngine

        mock_db = MagicMock()
        with patch("app.core.ai.agent.CredentialStore") as MockStore, \
             patch("app.core.ai.agent.AIProviderRegistry") as MockReg:

            store = MockStore.return_value
            store.get_config.return_value = self._mock_config()
            store.get_next_provider.return_value = {
                "id": "p1", "provider": "openai", "api_key": "k", "base_url": "", "model": "gpt-4o",
            }

            mock_provider = AsyncMock()
            mock_provider.chat.return_value = ChatResponse(
                content="",
                tool_calls=[ToolCall(id="c1", name="create_finding", arguments={"title": "X", "severity": "high"})],
                provider_id="p1",
            )
            MockReg.get.return_value = mock_provider

            engine = AgentEngine(mock_db)
            result = await engine.run(
                messages=[ChatMessage(role="user", content="create a finding")],
                pid="p1",
                agent_mode=True,
                confirmed_tools=[],
            )
            assert result.confirmed is False
            assert any(s.type == "confirmation_needed" for s in result.steps)

    @pytest.mark.asyncio
    async def test_write_tool_with_confirmation_proceeds(self):
        from app.core.ai.agent import AgentEngine

        mock_db = MagicMock()
        with patch("app.core.ai.agent.CredentialStore") as MockStore, \
             patch("app.core.ai.agent.AIProviderRegistry") as MockReg, \
             patch("app.core.ai.agent.tool_registry") as mock_tr:

            store = MockStore.return_value
            store.get_config.return_value = self._mock_config()
            store.get_next_provider.return_value = {
                "id": "p1", "provider": "openai", "api_key": "k", "base_url": "", "model": "gpt-4o",
            }

            mock_provider = AsyncMock()
            call_count = [0]

            async def mock_chat(**kwargs):
                call_count[0] += 1
                if call_count[0] == 1:
                    return ChatResponse(
                        content="",
                        tool_calls=[ToolCall(id="c1", name="create_finding",
                                             arguments={"title": "X", "severity": "high"})],
                        provider_id="p1",
                    )
                return ChatResponse(content="Finding created!", provider_id="p1")

            mock_provider.chat = mock_chat
            MockReg.get.return_value = mock_provider

            from app.core.ai.tool_registry import RiskLevel
            mock_td = MagicMock()
            mock_td.risk = RiskLevel.WRITE
            mock_tr.get.return_value = mock_td
            mock_tr.to_openai.return_value = []
            mock_tr.execute = AsyncMock(return_value={"id": "f1", "title": "X"})

            engine = AgentEngine(mock_db)
            result = await engine.run(
                messages=[ChatMessage(role="user", content="create a finding")],
                pid="p1",
                agent_mode=True,
                confirmed_tools=[{"name": "create_finding", "arguments": {"title": "X", "severity": "high"}}],
            )
            assert result.confirmed is True
            assert result.tool_calls_made >= 1


# ── Model Tests ───────────────────────────────────────────────────────


class TestAIModels:
    def test_models_importable(self):
        from app.models import AIChat, AIMessage, AIAuditLog
        assert AIChat.__tablename__ == "ai_chats"
        assert AIMessage.__tablename__ == "ai_messages"
        assert AIAuditLog.__tablename__ == "ai_audit_log"

    def test_chat_has_required_columns(self):
        from app.models import AIChat
        cols = {c.name for c in AIChat.__table__.columns}
        assert {"id", "pid", "user_id", "title", "provider_id", "model", "agent_mode"}.issubset(cols)

    def test_message_has_required_columns(self):
        from app.models import AIMessage
        cols = {c.name for c in AIMessage.__table__.columns}
        assert {"id", "chat_id", "seq", "role", "content", "tool_calls"}.issubset(cols)

    def test_audit_has_required_columns(self):
        from app.models import AIAuditLog
        cols = {c.name for c in AIAuditLog.__table__.columns}
        assert {"id", "pid", "action", "tool_name", "risk_level", "status"}.issubset(cols)
