"""
Ollama provider adapter — local LLM inference.

Uses the Ollama REST API (``/api/chat``) which has a slightly different
format from OpenAI but is OpenAI-compatible at ``/v1/chat/completions``.
We use the native API for richer features (model listing, keep-alive).
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from ..provider import (
    AIProvider,
    AIProviderRegistry,
    ChatMessage,
    ChatResponse,
    CredentialField,
    ToolCall,
)

logger = logging.getLogger(__name__)

_DEFAULT_BASE_URL = "http://localhost:11434"
_DEFAULT_MODELS = ["llama3.2", "qwen2.5", "mistral", "phi3", "gemma2"]


def _client(credentials: dict, **kw) -> httpx.AsyncClient:
    """Egress factory: proxy-pool rule "ai" + ai_provider:{id} target."""
    from ...net import egress_async_client

    return egress_async_client("ai", f"ai_provider:{credentials.get('id', '')}", **kw)


@AIProviderRegistry.register("ollama")

class OllamaProvider(AIProvider):

    @staticmethod
    def get_type() -> str:
        return "ollama"

    @staticmethod
    def get_display_name() -> str:
        return "Ollama (Local)"

    @staticmethod
    def get_category() -> str:
        return "local"

    @staticmethod
    def supports_tools() -> bool:
        return True

    @staticmethod
    def supports_streaming() -> bool:
        return True

    @staticmethod
    def get_default_models() -> list[str]:
        return list(_DEFAULT_MODELS)

    @staticmethod
    def get_credentials_schema() -> list[CredentialField]:
        return [
            CredentialField(
                "base_url",
                "Base URL",
                "text",
                required=False,
                default=_DEFAULT_BASE_URL,
                placeholder=_DEFAULT_BASE_URL,
                help_text="Ollama server URL (default: http://localhost:11434)",
            ),
        ]

    async def connect(self, credentials: dict) -> dict:
        base_url = credentials.get("base_url", "").rstrip("/") or _DEFAULT_BASE_URL
        try:
            from ...ssrf_guard import validate_outbound_url

            validate_outbound_url(base_url, allow_private=True)
        except Exception:
            return {"ok": False, "message": f"URL blocked by SSRF guard: {base_url}"}
        try:
            async with _client(credentials, timeout=10) as client:
                resp = await client.get(f"{base_url}/api/tags")
                if resp.status_code == 200:
                    return {"ok": True, "message": "Connected"}
                return {"ok": False, "message": f"HTTP {resp.status_code}"}
        except httpx.ConnectError:
            return {"ok": False, "message": "Ollama not running (connection refused)"}
        except Exception as e:
            return {"ok": False, "message": str(e)}

    async def list_models(self, credentials: dict) -> list[dict]:
        base_url = credentials.get("base_url", "").rstrip("/") or _DEFAULT_BASE_URL
        async with _client(credentials, timeout=15) as client:
            resp = await client.get(f"{base_url}/api/tags")
            resp.raise_for_status()
            data = resp.json()
            return [
                {"id": m.get("name", ""), "name": m.get("name", ""), "size": m.get("size", 0)}
                for m in data.get("models", [])
            ]

    async def chat(
        self,
        messages: list[ChatMessage],
        credentials: dict,
        model: str,
        tools: list[dict] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs,
    ) -> ChatResponse:
        base_url = credentials.get("base_url", "").rstrip("/") or _DEFAULT_BASE_URL

        ollama_msgs = []
        for msg in messages:
            d: dict[str, Any] = {"role": msg.role, "content": msg.content}
            if msg.tool_calls:
                d["tool_calls"] = [tc.to_openai_dict() for tc in msg.tool_calls]
            if msg.tool_call_id:
                d["tool_call_id"] = msg.tool_call_id
            ollama_msgs.append(d)

        body: dict[str, Any] = {
            "model": model,
            "messages": ollama_msgs,
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        if tools:
            body["tools"] = tools

        async with _client(credentials, timeout=300) as client:
            resp = await client.post(f"{base_url}/api/chat", json=body)
            if resp.status_code == 429:
                raise _RateLimitError()
            resp.raise_for_status()
            return _parse_response(resp.json(), model)

    async def chat_stream(
        self,
        messages: list[ChatMessage],
        credentials: dict,
        model: str,
        tools: list[dict] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs,
    ):
        base_url = credentials.get("base_url", "").rstrip("/") or _DEFAULT_BASE_URL

        ollama_msgs = []
        for msg in messages:
            d: dict[str, Any] = {"role": msg.role, "content": msg.content}
            if msg.tool_calls:
                d["tool_calls"] = [tc.to_openai_dict() for tc in msg.tool_calls]
            if msg.tool_call_id:
                d["tool_call_id"] = msg.tool_call_id
            ollama_msgs.append(d)

        body: dict[str, Any] = {
            "model": model,
            "messages": ollama_msgs,
            "stream": True,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        if tools:
            body["tools"] = tools

        content_buf = ""
        try:
            async with _client(credentials, timeout=300) as client:
                async with client.stream("POST", f"{base_url}/api/chat", json=body) as resp:
                    if resp.status_code == 429:
                        raise _RateLimitError()
                    resp.raise_for_status()

                    async for line in resp.aiter_lines():
                        if not line.strip():
                            continue
                        try:
                            chunk = json.loads(line)
                        except json.JSONDecodeError:
                            continue

                        msg_data = chunk.get("message", {})
                        text = msg_data.get("content", "")
                        if text:
                            content_buf += text
                            yield {"type": "content", "text": text}

                        tool_calls = msg_data.get("tool_calls", [])
                        if tool_calls:
                            parsed_tcs = []
                            for tc in tool_calls:
                                fn = tc.get("function", {})
                                raw = fn.get("arguments", "{}")
                                args = raw
                                if isinstance(raw, str):
                                    try:
                                        args = json.loads(raw)
                                    except json.JSONDecodeError:
                                        args = {}
                                parsed_tcs.append(
                                    ToolCall(
                                        id=tc.get("id", ""),
                                        name=fn.get("name", ""),
                                        arguments=args,
                                        arguments_raw=(
                                            raw if isinstance(raw, str) else json.dumps(raw)
                                        ),
                                    )
                                )
                            yield {
                                "type": "tool_calls",
                                "tool_calls": [tc.__dict__ for tc in parsed_tcs],
                            }

                        if chunk.get("done"):
                            break
        except _RateLimitError:
            raise
        except (httpx.ReadError, httpx.RemoteProtocolError, httpx.ConnectError) as e:
            logger.warning(
                "[ollama_stream] connection interrupted: %s (content so far: %d chars)",
                e,
                len(content_buf),
            )
        except Exception as e:
            if "input stream" in str(e).lower():
                logger.warning(
                    "[ollama_stream] input stream error after %d chars", len(content_buf)
                )
            else:
                raise

        yield {"type": "done", "content": content_buf}


class _RateLimitError(Exception):
    pass


def _parse_response(data: dict, model: str) -> ChatResponse:
    msg = data.get("message", {})
    content = msg.get("content", "")

    tool_calls = []
    for tc in msg.get("tool_calls") or []:
        fn = tc.get("function", {})
        raw = fn.get("arguments", "{}")
        args = {}
        if isinstance(raw, str):
            try:
                args = json.loads(raw)
            except json.JSONDecodeError:
                pass
        else:
            args = raw
        tool_calls.append(
            ToolCall(
                id=tc.get("id", ""),
                name=fn.get("name", ""),
                arguments=args,
                arguments_raw=raw if isinstance(raw, str) else json.dumps(raw),
            )
        )

    return ChatResponse(
        content=content,
        tool_calls=tool_calls or None,
        provider_id="ollama",
        model=model,
        usage={
            "prompt_tokens": data.get("prompt_eval_count", 0),
            "completion_tokens": data.get("eval_count", 0),
            "total_tokens": data.get("prompt_eval_count", 0) + data.get("eval_count", 0),
        },
        finish_reason="stop" if data.get("done") else "",
    )
