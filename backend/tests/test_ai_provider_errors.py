"""AI providers: connection/chat error taxonomy (Shannon 2026-10-29).

The hardening rewrote every failure path so provider errors never
reflect the target URL or low-level socket vocabulary back to the chat
UI. These tests pin each branch: refused/timeout/proxy connects,
upstream HTTP codes, rate limiting, SSRF-guarded URLs and the generic
fallback."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from fastapi import HTTPException

from app.core.ai.provider import AIProviderRegistry, ChatMessage


def _response(status=200, payload=None):
    r = MagicMock()
    r.status_code = status
    r.json.return_value = payload if payload is not None else {}

    def _raise():
        if status >= 400:
            raise httpx.HTTPStatusError(
                "server error", request=MagicMock(url="http://unit.test"), response=r
            )

    r.raise_for_status = _raise
    return r


def _async_client_ctx(get=None, post=None):
    """Patches a provider module's _client(): async context manager."""
    client = MagicMock()
    if get is not None:
        client.get = (
            AsyncMock(side_effect=get)
            if isinstance(get, Exception)
            else AsyncMock(return_value=get)
        )
    if post is not None:
        client.post = (
            AsyncMock(side_effect=post)
            if isinstance(post, Exception)
            else AsyncMock(return_value=post)
        )
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=client)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


def _provider(ptype):
    p = AIProviderRegistry.get(ptype)
    assert p is not None
    return p


class TestOpenAICompatConnect:
    @pytest.fixture
    def mod(self):
        from app.core.ai.providers import openai_compat as m

        return m

    async def test_ok(self, mod):
        with patch.object(mod, "_client", return_value=_async_client_ctx(get=_response(200))):
            r = await _provider("openai").connect({"api_key": "sk-x"})
            assert r == {"ok": True, "message": "Connected"}

    async def test_invalid_api_key(self, mod):
        with patch.object(mod, "_client", return_value=_async_client_ctx(get=_response(401))):
            r = await _provider("openai").connect({"api_key": "bad"})
            assert r == {"ok": False, "message": "Invalid API key"}

    async def test_upstream_http_code(self, mod):
        with patch.object(mod, "_client", return_value=_async_client_ctx(get=_response(503))):
            r = await _provider("openai").connect({"api_key": "sk-x"})
            assert r == {"ok": False, "message": "HTTP 503"}

    @pytest.mark.parametrize(
        "exc", [httpx.ConnectError("refused"), httpx.ConnectTimeout("t"), httpx.ProxyError("p")]
    )
    async def test_connection_failures_never_leak_details(self, mod, exc):
        with patch.object(mod, "_client", return_value=_async_client_ctx(get=exc)):
            r = await _provider("openai").connect({"api_key": "sk-x"})
            assert r == {"ok": False, "message": "Connection failed"}

    async def test_status_error_exception(self, mod):
        boom = _response(500)

        def _raise_status():
            raise httpx.HTTPStatusError("e", request=MagicMock(), response=boom)

        resp = _response(200)
        resp.status_code = 500
        resp.raise_for_status = _raise_status
        with patch.object(mod, "_client", return_value=_async_client_ctx(get=resp)):
            r = await _provider("openai").connect({"api_key": "sk-x"})
            assert r == {"ok": False, "message": "HTTP 500"}

    async def test_generic_fallback(self, mod):
        with patch.object(mod, "_client", return_value=_async_client_ctx(get=RuntimeError("sock"))):
            r = await _provider("openai").connect({"api_key": "sk-x"})
            assert r == {"ok": False, "message": "Connection failed"}

    async def test_ssrf_blocked_url(self, mod):
        with patch(
            "app.core.ssrf_guard.validate_outbound_url",
            side_effect=HTTPException(400, "nope"),
        ):
            r = await _provider("openai").connect({"api_key": "sk-x", "base_url": "ftp://x"})
            assert r["ok"] is False
            assert r["message"].startswith("URL blocked by SSRF guard")


class TestAnthropicConnect:
    @pytest.fixture
    def mod(self):
        from app.core.ai.providers import anthropic as m

        return m

    async def test_ok(self, mod):
        with patch.object(mod, "_client", return_value=_async_client_ctx(post=_response(200))):
            r = await _provider("anthropic").connect({"api_key": "k"})
            assert r == {"ok": True, "message": "Connected"}

    async def test_bad_request_still_means_reachable(self, mod):
        # a 400 from /v1/messages proves the endpoint answered
        with patch.object(mod, "_client", return_value=_async_client_ctx(post=_response(400))):
            r = await _provider("anthropic").connect({"api_key": "k"})
            assert r == {"ok": True, "message": "Connected"}

    async def test_invalid_api_key(self, mod):
        with patch.object(mod, "_client", return_value=_async_client_ctx(post=_response(401))):
            r = await _provider("anthropic").connect({"api_key": "bad"})
            assert r == {"ok": False, "message": "Invalid API key"}

    async def test_http_error_code(self, mod):
        with patch.object(mod, "_client", return_value=_async_client_ctx(post=_response(529))):
            r = await _provider("anthropic").connect({"api_key": "k"})
            assert r == {"ok": False, "message": "HTTP 529"}

    async def test_connect_refused(self, mod):
        with patch.object(
            mod, "_client", return_value=_async_client_ctx(post=httpx.ConnectError("x"))
        ):
            r = await _provider("anthropic").connect({"api_key": "k"})
            assert r == {"ok": False, "message": "Connection failed"}

    async def test_generic_fallback(self, mod):
        with patch.object(mod, "_client", return_value=_async_client_ctx(get=ValueError("v"))):
            r = await _provider("anthropic").connect({"api_key": "k"})
            assert r == {"ok": False, "message": "Connection failed"}

    async def test_ssrf_blocked_url(self, mod):
        with patch(
            "app.core.ssrf_guard.validate_outbound_url",
            side_effect=HTTPException(400, "nope"),
        ):
            r = await _provider("anthropic").connect({"api_key": "k", "base_url": "gopher://h"})
            assert r["ok"] is False


class TestOllamaConnect:
    @pytest.fixture
    def mod(self):
        from app.core.ai.providers import ollama as m

        return m

    async def test_ok(self, mod):
        with patch.object(mod, "_client", return_value=_async_client_ctx(get=_response(200))):
            r = await _provider("ollama").connect({})
            assert r == {"ok": True, "message": "Connected"}

    async def test_not_running(self, mod):
        with patch.object(
            mod, "_client", return_value=_async_client_ctx(get=httpx.ConnectError("refused"))
        ):
            r = await _provider("ollama").connect({})
            assert r == {"ok": False, "message": "Ollama not running (connection refused)"}

    async def test_http_error_code(self, mod):
        with patch.object(mod, "_client", return_value=_async_client_ctx(get=_response(404))):
            r = await _provider("ollama").connect({})
            assert r == {"ok": False, "message": "HTTP 404"}

    async def test_ssrf_blocked_url(self, mod):
        with patch(
            "app.core.ssrf_guard.validate_outbound_url",
            side_effect=HTTPException(400, "nope"),
        ):
            r = await _provider("ollama").connect({"base_url": "ftp://nope"})
            assert r["ok"] is False


class TestChatErrorPaths:
    """chat() must raise typed errors, never leak URLs in messages."""

    @pytest.fixture
    def msgs(self):
        return [ChatMessage(role="user", content="hi")]

    @pytest.fixture
    def oc(self):
        from app.core.ai.providers import openai_compat as m

        return m

    @pytest.fixture
    def an(self):
        from app.core.ai.providers import anthropic as m

        return m

    async def test_openai_rate_limit(self, msgs, oc):
        from app.core.ai.providers.openai_compat import _RateLimitError

        with patch.object(oc, "_client", return_value=_async_client_ctx(post=_response(429))):
            with pytest.raises(_RateLimitError):
                await _provider("openai").chat(msgs, {"api_key": "k"}, model="gpt-test")

    async def test_openai_upstream_error_has_no_url(self, msgs, oc):
        with patch.object(oc, "_client", return_value=_async_client_ctx(post=_response(500))):
            with pytest.raises(RuntimeError) as ei:
                await _provider("openai").chat(msgs, {"api_key": "k"}, model="gpt-test")
            assert str(ei.value) == "provider returned HTTP 500"

    async def test_anthropic_rate_limit(self, msgs, an):
        from app.core.ai.providers.anthropic import _RateLimitError

        with patch.object(an, "_client", return_value=_async_client_ctx(post=_response(429))):
            with pytest.raises(_RateLimitError):
                await _provider("anthropic").chat(msgs, {"api_key": "k"}, model="claude-test")

    async def test_anthropic_upstream_error(self, msgs, an):
        with patch.object(an, "_client", return_value=_async_client_ctx(post=_response(500))):
            with pytest.raises(RuntimeError, match="provider returned HTTP 500"):
                await _provider("anthropic").chat(msgs, {"api_key": "k"}, model="claude-test")

    async def test_openai_ssrf_guard_raises(self, msgs):
        with patch(
            "app.core.ssrf_guard.validate_outbound_url",
            side_effect=HTTPException(400, "blocked"),
        ):
            with pytest.raises(HTTPException):
                await _provider("openai").chat(
                    msgs, {"api_key": "k", "base_url": "http://169.254.169.254"}, model="m"
                )


class TestListModels:
    async def test_openai_models_parsed(self):
        from app.core.ai.providers import openai_compat as m

        payload = {"data": [{"id": "gpt-x"}, {"id": "gpt-y"}]}
        with patch.object(
            m, "_client", return_value=_async_client_ctx(get=_response(200, payload))
        ):
            models = await _provider("openai").list_models({"api_key": "k"})
            assert [x["id"] for x in models] == ["gpt-x", "gpt-y"]


class TestOllamaChat:
    @pytest.fixture
    def mod(self):
        from app.core.ai.providers import ollama as m

        return m

    @pytest.fixture
    def msgs(self):
        return [ChatMessage(role="user", content="hi")]

    async def test_rate_limit(self, mod, msgs):
        from app.core.ai.providers.ollama import _RateLimitError

        with patch.object(mod, "_client", return_value=_async_client_ctx(post=_response(429))):
            with pytest.raises(_RateLimitError):
                await _provider("ollama").chat(msgs, {}, model="llama3")

    async def test_upstream_error_has_no_url(self, mod, msgs):
        with patch.object(mod, "_client", return_value=_async_client_ctx(post=_response(500))):
            with pytest.raises(RuntimeError, match="provider returned HTTP 500"):
                await _provider("ollama").chat(msgs, {}, model="llama3")

    async def test_success_returns_parsed(self, mod, msgs):
        sentinel = object()
        with (
            patch.object(mod, "_client", return_value=_async_client_ctx(post=_response(200))),
            patch.object(mod, "_parse_response", return_value=sentinel),
        ):
            r = await _provider("ollama").chat(msgs, {}, model="llama3")
            assert r is sentinel

    async def test_messages_carry_tool_fields(self, mod):
        from app.core.ai.provider import ToolCall

        msg = ChatMessage(
            role="tool",
            content="out",
            tool_calls=[ToolCall(id="t1", name="scan", arguments={"a": 1})],
            tool_call_id="t1",
            name="scan",
        )
        client = MagicMock()
        client.post = AsyncMock(return_value=_response(200))
        cm = MagicMock()
        cm.__aenter__ = AsyncMock(return_value=client)
        cm.__aexit__ = AsyncMock(return_value=False)
        with (
            patch.object(mod, "_client", return_value=cm),
            patch.object(mod, "_parse_response", return_value=object()),
        ):
            await _provider("ollama").chat([msg], {}, model="llama3")
            sent = client.post.call_args[1]["json"]["messages"][0]
            assert sent["role"] == "tool" and sent["tool_call_id"] == "t1"
            assert sent["tool_calls"][0]["type"] == "function"

    async def test_ssrf_guard_raises(self, mod, msgs):
        with patch(
            "app.core.ssrf_guard.validate_outbound_url",
            side_effect=HTTPException(400, "blocked"),
        ):
            with pytest.raises(HTTPException):
                await _provider("ollama").chat(
                    msgs, {"base_url": "http://169.254.169.254"}, model="m"
                )


class TestChatSuccessReturnsParsed:
    @pytest.fixture
    def oc(self):
        from app.core.ai.providers import openai_compat as m

        return m

    @pytest.fixture
    def an(self):
        from app.core.ai.providers import anthropic as m

        return m

    async def test_openai(self, oc):
        sentinel = object()
        with (
            patch.object(oc, "_client", return_value=_async_client_ctx(post=_response(200))),
            patch.object(oc, "_parse_response", return_value=sentinel),
        ):
            r = await _provider("openai").chat(
                [ChatMessage(role="user", content="hi")], {"api_key": "k"}, model="gpt-test"
            )
            assert r is sentinel

    async def test_anthropic(self, an):
        sentinel = object()
        with (
            patch.object(an, "_client", return_value=_async_client_ctx(post=_response(200))),
            patch.object(an, "_parse_response", return_value=sentinel),
        ):
            r = await _provider("anthropic").chat(
                [ChatMessage(role="user", content="hi")], {"api_key": "k"}, model="claude-test"
            )
            assert r is sentinel


class TestParseResponse:
    """openai_compat._parse_response: think-tag stripping + tool args."""

    @pytest.fixture
    def parse(self):
        from app.core.ai.providers.openai_compat import _parse_response

        return _parse_response

    def test_empty_choices(self, parse):
        r = parse({}, "openai")
        assert r.provider_id == "openai"
        assert r.content == ""

    def test_think_tags_stripped(self, parse):
        data = {"choices": [{"message": {"content": "<think>reasoning</think>Answer"}}]}
        r = parse(data, "openai")
        assert r.content == "Answer"

    def test_tool_call_string_arguments_parsed(self, parse):
        data = {
            "choices": [
                {
                    "message": {
                        "content": "",
                        "tool_calls": [
                            {"id": "t1", "function": {"name": "scan", "arguments": '{"a": 1}'}}
                        ],
                    }
                }
            ]
        }
        r = parse(data, "openai")
        assert r.tool_calls and r.tool_calls[0].arguments == {"a": 1}
        assert r.tool_calls[0].arguments_raw == '{"a": 1}'

    def test_tool_call_dict_arguments_kept(self, parse):
        data = {
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {"id": "t2", "function": {"name": "go", "arguments": {"b": 2}}}
                        ]
                    }
                }
            ]
        }
        r = parse(data, "openai")
        assert r.tool_calls[0].arguments == {"b": 2}

    def test_tool_call_bad_json_arguments_empty(self, parse):
        data = {
            "choices": [
                {
                    "message": {
                        "tool_calls": [
                            {"id": "t3", "function": {"name": "go", "arguments": "{not json"}}
                        ]
                    }
                }
            ]
        }
        r = parse(data, "openai")
        assert r.tool_calls[0].arguments == {}
        assert r.tool_calls[0].arguments_raw == "{not json"


def _sse_resp(status=200, lines=None, raise_status=False):
    """Response mock for chat_stream: status + SSE lines via aiter_lines."""
    resp = MagicMock()
    resp.status_code = status

    async def _aiter():
        for ln in lines or []:
            yield ln

    resp.aiter_lines = lambda: _aiter()

    def _raise():
        if raise_status:
            raise httpx.HTTPStatusError("e", request=MagicMock(), response=resp)

    resp.raise_for_status = _raise
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=resp)
    cm.__aexit__ = AsyncMock(return_value=False)
    return cm


def _stream_client(resp_cm):
    client = MagicMock()
    client.stream = MagicMock(return_value=resp_cm)
    outer = MagicMock()
    outer.__aenter__ = AsyncMock(return_value=client)
    outer.__aexit__ = AsyncMock(return_value=False)
    return outer


class TestChatStreamErrorPaths:
    @pytest.fixture
    def msgs(self):
        return [ChatMessage(role="user", content="hi")]

    @pytest.fixture
    def oc(self):
        from app.core.ai.providers import openai_compat as m

        return m

    async def test_openai_rate_limit(self, oc, msgs):
        from app.core.ai.providers.openai_compat import _RateLimitError

        with patch.object(oc, "_client", return_value=_stream_client(_sse_resp(status=429))):
            with pytest.raises(_RateLimitError):
                async for _ in _provider("openai").chat_stream(msgs, {"api_key": "k"}, model="m"):
                    pass

    async def test_openai_upstream_error_no_url(self, oc, msgs):
        with patch.object(
            oc, "_client", return_value=_stream_client(_sse_resp(status=500, raise_status=True))
        ):
            with pytest.raises(RuntimeError, match="provider returned HTTP 500"):
                async for _ in _provider("openai").chat_stream(msgs, {"api_key": "k"}, model="m"):
                    pass


class TestChatStreamHappyPath:
    @pytest.fixture
    def oc(self):
        from app.core.ai.providers import openai_compat as m

        return m

    async def test_openai_reasoning_content_toolcalls_done(self, oc):
        lines = [
            'data: {"choices":[{"delta":{"reasoning_content":"thinking"}}]}',
            "data: not-json-at-all",
            'data: {"choices":[{"delta":{"content":"Hello"}}]}',
            'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"t1","function":{"name":"scan","arguments":"{}"}}]}}]}',
            "data: [DONE]",
        ]
        with patch.object(
            oc, "_client", return_value=_stream_client(_sse_resp(status=200, lines=lines))
        ):
            events = [
                e
                async for e in _provider("openai").chat_stream(
                    [ChatMessage(role="user", content="hi")], {"api_key": "k"}, model="m"
                )
            ]
        kinds = [e["type"] for e in events]
        assert "reasoning" in kinds and kinds[-1] == "done"
        content = next(e for e in events if e["type"] == "content")
        assert content["text"] == "Hello"
        final = events[-1]
        assert final["content"] == "Hello"  # buffered content flushed at done
        tc = [e for e in events if e["type"] == "tool_calls"]
        assert tc, "tool_calls event expected"
        assert tc[0]["tool_calls"][0]["name"] == "scan"


class TestOllamaExtras:
    @pytest.fixture
    def mod(self):
        from app.core.ai.providers import ollama as m

        return m

    async def test_connect_generic_exception_message(self, mod):
        with patch.object(
            mod, "_client", return_value=_async_client_ctx(get=RuntimeError("dns broke"))
        ):
            r = await _provider("ollama").connect({})
            assert r == {"ok": False, "message": "dns broke"}

    async def test_list_models(self, mod):
        payload = {"models": [{"name": "llama3:8b"}, {"name": "nomic-embed"}]}
        with patch.object(
            mod, "_client", return_value=_async_client_ctx(get=_response(200, payload))
        ):
            models = await _provider("ollama").list_models({})
            assert [m["id"] for m in models] == ["llama3:8b", "nomic-embed"]
