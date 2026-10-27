"""AI anonymizer: outgoing tokenization + restoration of model output."""

import json

import pytest

from app.core.ai.anonymizer import Anonymizer
from app.core.ai.provider import ChatMessage


def test_roundtrip_all_kinds():
    a = Anonymizer()
    real = "scan 10.0.0.5 then 192.168.1.10, dc01.corp.local, CORP\\adm_login, op@corp.local"
    out = a.anonymize(real)
    assert "10.0.0.5" not in out and "dc01.corp.local" not in out
    assert "[IP_1]" in out and "[IP_2]" in out and "[HOST_1]" in out and "[USER_1]" in out and "[EMAIL_1]" in out
    assert a.restore(out) == real


def test_stable_tokens_same_value():
    a = Anonymizer()
    out = a.anonymize("10.0.0.5 ... 10.0.0.5 ... 10.0.0.5")
    assert out.count("[IP_1]") == 3


def test_stream_split_token():
    a = Anonymizer()
    a.anonymize("dc01.corp.local 10.0.0.5")
    parts = ["check [HO", "ST_1] first, ", "then [IP_", "1] too"]
    rendered = "".join(a.restore_stream_chunk(p) for p in parts) + a.flush()
    assert rendered == "check dc01.corp.local first, then 10.0.0.5 too"


def test_restore_args_nested():
    a = Anonymizer()
    a.anonymize("10.0.0.7 dc01.corp.local")
    args = {"host": "[IP_1]", "extra": {"target": "[HOST_1]"}, "n": 5}
    restored = a.restore_args(args)
    assert restored["host"] == "10.0.0.7"
    assert restored["extra"]["target"] == "dc01.corp.local"
    assert restored["n"] == 5


def test_messages_preserve_tool_protocol():
    a = Anonymizer()
    a.anonymize("10.0.0.9")
    msgs = [
        ChatMessage(role="system", content="sys 10.0.0.9"),
        ChatMessage(role="user", content="scan 10.0.0.9"),
        ChatMessage(role="assistant", content="calling", tool_calls=[
            type("TC", (), {"model_dump": lambda self: {"id": "t1", "name": "list_hosts", "arguments": {"query": "10.0.0.9"}}})()
        ]),
        ChatMessage(role="tool", content='[{"ip": "10.0.0.9"}]', tool_call_id="t1", name="list_hosts"),
    ]
    out = a.anonymize_messages(msgs)
    assert out[0].content == "sys [IP_1]"
    assert out[1].content == "scan [IP_1]"
    assert out[2].tool_calls is not None and "10.0.0.9" not in json.dumps(out[2].tool_calls[0]["arguments"])
    assert out[3].tool_call_id == "t1" and "[IP_1]" in out[3].content


def test_no_identifiers_untouched():
    a = Anonymizer()
    assert a.anonymize("just plain words, no secrets here") == "just plain words, no secrets here"
    assert a.active is False


class TestAgentIntegration:
    """Полный цикл: провайдер с anonymize=True — наружу токены, юзеру реальность."""

    @pytest.mark.asyncio
    async def test_outgoing_tokenized_and_answer_restored(self):
        from unittest.mock import AsyncMock, MagicMock, patch

        from app.core.ai.agent import AgentEngine
        from app.core.ai.provider import ChatResponse

        captured = {}

        async def fake_chat(messages, credentials, model, tools=None, **kw):
            captured["messages"] = list(messages)
            return ChatResponse(content="Проверь [HOST_1] и [IP_1]", tool_calls=None,
                                provider_id="p1", model="m")

        mock_db = MagicMock()
        with patch("app.core.ai.agent.CredentialStore") as MockStore, \
             patch("app.core.ai.agent.AIProviderRegistry") as MockReg:
            store = MockStore.return_value
            store.get_config.return_value = {"max_tool_calls": 5, "agent_mode": False,
                                             "block_critical_tools": True,
                                             "require_confirmation_writes": True}
            store.get_next_provider.return_value = {
                "id": "p1", "provider": "openai", "api_key": "k", "base_url": "",
                "model": "m", "anonymize": True,
            }
            store.list_providers.return_value = [{"id": "p1", "anonymize": True}]
            MockReg.get.return_value = MagicMock()
            MockReg.get.return_value.chat = fake_chat

            engine = AgentEngine(mock_db)
            result = await engine.run(
                messages=[ChatMessage(role="user", content="Что на dc01.corp.local (10.0.0.5)?")],
                pid="p1", agent_mode=False,
            )

        sent = " ".join(m.content for m in captured["messages"])
        assert "dc01.corp.local" not in sent and "10.0.0.5" not in sent
        assert "[HOST_1]" in sent and "[IP_1]" in sent
        assert result.content == "Проверь dc01.corp.local и 10.0.0.5"

    @pytest.mark.asyncio
    async def test_tool_args_tokens_restored_before_execute(self):
        from unittest.mock import MagicMock, patch

        from app.core.ai import agent as agent_mod
        from app.core.ai.agent import AgentEngine
        from app.core.ai.provider import ChatResponse, ToolCall

        executed = {}

        async def fake_chat(messages, credentials, model, tools=None, **kw):
            if not getattr(fake_chat, "called", False):
                fake_chat.called = True
                return ChatResponse(
                    content="", provider_id="p1", model="m",
                    tool_calls=[ToolCall(id="t1", name="list_hosts", arguments={"query": "[IP_1]"})],
                )
            return ChatResponse(content="готово для [IP_1]", tool_calls=None, provider_id="p1", model="m")

        async def fake_execute(db, pid, name, args, user_id=None):
            executed["args"] = dict(args)
            executed["name"] = name
            return [{"ip": "10.0.0.5", "hostname": "dc01.corp.local"}]

        mock_db = MagicMock()
        with patch("app.core.ai.agent.CredentialStore") as MockStore, \
             patch("app.core.ai.agent.AIProviderRegistry") as MockReg, \
             patch.object(agent_mod.tool_registry, "execute", fake_execute):
            store = MockStore.return_value
            store.get_config.return_value = {"max_tool_calls": 5, "agent_mode": True,
                                             "block_critical_tools": True,
                                             "require_confirmation_writes": False}
            store.get_next_provider.return_value = {
                "id": "p1", "provider": "openai", "api_key": "k", "base_url": "",
                "model": "m", "anonymize": True,
            }
            store.list_providers.return_value = [{"id": "p1", "anonymize": True}]
            MockReg.get.return_value = MagicMock()
            MockReg.get.return_value.chat = fake_chat

            engine = AgentEngine(mock_db)
            result = await engine.run(
                messages=[ChatMessage(role="user", content="проверь 10.0.0.5")],
                pid="p1", agent_mode=True,
            )

        assert executed["name"] == "list_hosts"
        assert executed["args"]["query"] == "10.0.0.5"  # токен восстановлен до реального IP
        assert result.content == "готово для 10.0.0.5"


class TestAnonymizeByDefault:
    """Regression: anonymization is opt-OUT. Providers without the field
    (created before it existed, or via API without the flag) must get
    tokenized outgoing traffic — real engagement data on the wire was
    found on a live stand."""

    def test_predicate_defaults_on(self):
        from app.core.ai.agent import _provider_wants_anonymize

        assert _provider_wants_anonymize({}) is True
        assert _provider_wants_anonymize({"anonymize": True}) is True
        assert _provider_wants_anonymize({"anonymize": False}) is False

    def test_engine_tokenizes_without_provider_flag(self, db, monkeypatch):
        """Provider row WITHOUT `anonymize` → the engine still builds an
        anonymizer and the provider receives [IP_1]-style tokens, not the
        real values the user typed."""
        import asyncio

        from app.core.utils import new_id, ts_now
        from app.models import GlobalSetting, Project

        p = Project(id=new_id("p"), name="anon-default", status="active", added=ts_now())
        db.add(p)
        db.add(
            GlobalSetting(
                key="ai_providers_v2",
                value={
                    "providers": [
                        {"id": "local", "provider": "openai", "model": "m", "base_url": "http://x", "api_key": "k", "enabled": True}
                    ]
                },
            )
        )
        db.commit()

        captured = {}

        from app.core.ai.agent import AgentEngine
        from app.core.ai.provider import AIProviderRegistry, ChatMessage, ChatResponse

        class Capture:
            async def chat(self, messages, credentials, model, tools=None, **kwargs):
                captured["content"] = messages[0].content if messages else ""
                return ChatResponse(content="done", provider_id="capture", model=model or "m", finish_reason="stop")

        monkeypatch.setattr(AIProviderRegistry, "get", classmethod(lambda cls, ptype: Capture()))
        eng = AgentEngine(db)
        asyncio.run(
            eng.run([ChatMessage(role="user", content="scan 10.0.0.5 on dc01.corp.local")], p.id)
        )
        assert "[IP_1]" in captured["content"]
        assert "10.0.0.5" not in captured["content"]
        assert "dc01.corp.local" not in captured["content"]


class TestToolCallTypesPreserved:
    """Regression: anonymize_messages must return tool calls of the SAME
    type it received. Round-tripping them to dicts crashed every second
    LLM round (provider: 'dict' object has no attribute 'to_openai_dict')
    the moment anonymization became the default — i.e. any agent run with
    tools died right after its first tool call."""

    def test_roundtrip_keeps_toolcall_class(self):
        from app.core.ai.agent import AgentEngine  # noqa: F401 — engine path sanity
        from app.core.ai.anonymizer import Anonymizer
        from app.core.ai.provider import ChatMessage, ToolCall

        a = Anonymizer()
        msgs = [
            ChatMessage(
                role="assistant",
                content="scanning [IP_1]",
                tool_calls=[
                    ToolCall(id="c1", name="run_command", arguments={"command": "nmap -Pn 10.124.2.10"})
                ],
            )
        ]
        out = a.anonymize_messages(msgs)
        tc = out[0].tool_calls[0]
        assert isinstance(tc, ToolCall), f"ToolCall превратился в {type(tc)}"
        assert tc.arguments["command"] == "nmap -Pn [IP_1]"
        # провайдер не должен падать на сериализации
        assert out[0].to_openai_dict()["tool_calls"][0]["function"]["name"] == "run_command"

    def test_engine_two_rounds_with_anonymizer(self, db, monkeypatch):
        import asyncio

        from app.core.utils import new_id, ts_now
        from app.models import GlobalSetting, Project

        p = Project(id=new_id("p"), name="two-rounds", status="active", added=ts_now())
        db.add(p)
        db.query(GlobalSetting).filter(GlobalSetting.key == "ai_providers_v2").delete()
        db.add(
            GlobalSetting(
                key="ai_providers_v2",
                value={"providers": [{"id": "x", "provider": "openai", "model": "m", "enabled": True, "api_key": "k"}]},
            )
        )
        db.commit()

        from app.core.ai.agent import AgentEngine
        from app.core.ai.provider import AIProviderRegistry, ChatMessage, ChatResponse, ToolCall

        calls = {"n": 0}
        received = []

        class P:
            async def chat(self, messages, credentials, model, tools=None, **kwargs):
                calls["n"] += 1
                received.append([type(m) for m in messages])
                if calls["n"] == 1:
                    return ChatResponse(
                        content="",
                        provider_id="x",
                        model=model,
                        tool_calls=[ToolCall(id="c1", name="list_hosts", arguments={})],
                    )
                # второй раунд: история уже содержит assistant+tool — здесь и падало
                for m in messages:
                    m.to_openai_dict()
                return ChatResponse(content="готово", provider_id="x", model=model, finish_reason="stop")

        monkeypatch.setattr(AIProviderRegistry, "get", classmethod(lambda cls, t: P()))
        res = asyncio.run(AgentEngine(db).run([ChatMessage(role="user", content="хосты?")], p.id))
        assert calls["n"] == 2
        assert res.content == "готово"
