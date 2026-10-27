"""
Anthropic Claude provider adapter.

Uses the Anthropic Messages API (``/v1/messages``) with content-block format.
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

_DEFAULT_BASE_URL = "https://api.anthropic.com"
_DEFAULT_MODELS = [
    "claude-sonnet-4-20250514",
    "claude-opus-4-20250514",
    "claude-haiku-4-5-20251001",
    "claude-3-5-sonnet-20241022",
    "claude-3-5-haiku-20241022",
]


def _client(credentials: dict, **kw) -> httpx.AsyncClient:
    """Egress factory: proxy-pool rule "ai" + ai_provider:{id} target."""
    from ...net import egress_async_client

    return egress_async_client("ai", f"ai_provider:{credentials.get('id', '')}", **kw)


@AIProviderRegistry.register("anthropic")

class AnthropicProvider(AIProvider):

    @staticmethod
    def get_type() -> str:
        return "anthropic"

    @staticmethod
    def get_display_name() -> str:
        return "Anthropic Claude"

    @staticmethod
    def get_category() -> str:
        return "cloud"

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
                "api_key", "API Key", "password", required=True, help_text="Anthropic API key"
            ),
            CredentialField(
                "base_url",
                "Base URL",
                "text",
                required=False,
                default=_DEFAULT_BASE_URL,
                placeholder=_DEFAULT_BASE_URL,
            ),
        ]

    async def connect(self, credentials: dict) -> dict:
        base_url = credentials.get("base_url", "").rstrip("/") or _DEFAULT_BASE_URL
        api_key = credentials.get("api_key", "")
        try:
            from ...ssrf_guard import validate_outbound_url

            validate_outbound_url(base_url, allow_private=True)
        except Exception:
            return {"ok": False, "message": f"URL blocked by SSRF guard: {base_url}"}
        try:
            async with _client(credentials, timeout=15) as client:
                headers = {
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                }
                body = {
                    "model": _DEFAULT_MODELS[0],
                    "max_tokens": 1,
                    "messages": [{"role": "user", "content": "hi"}],
                }
                resp = await client.post(f"{base_url}/v1/messages", json=body, headers=headers)
                if resp.status_code == 401:
                    return {"ok": False, "message": "Invalid API key"}
                if resp.status_code in (200, 400):
                    return {"ok": True, "message": "Connected"}
                return {"ok": False, "message": f"HTTP {resp.status_code}"}
        except httpx.ConnectError:
            return {"ok": False, "message": "Connection refused"}
        except Exception as e:
            return {"ok": False, "message": str(e)}

    async def list_models(self, credentials: dict) -> list[dict]:
        return [{"id": m, "name": m} for m in _DEFAULT_MODELS]

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
        api_key = credentials.get("api_key", "")

        system, anthropic_msgs = _convert_messages(messages)
        body: dict[str, Any] = {
            "model": model,
            "messages": anthropic_msgs,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if system:
            body["system"] = system
        if tools:
            body["tools"] = _convert_tools(tools)

        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        async with _client(credentials, timeout=300) as client:
            resp = await client.post(f"{base_url}/v1/messages", json=body, headers=headers)
            if resp.status_code == 429:
                raise _RateLimitError()
            resp.raise_for_status()
            return _parse_response(resp.json())

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
        api_key = credentials.get("api_key", "")

        system, anthropic_msgs = _convert_messages(messages)
        body: dict[str, Any] = {
            "model": model,
            "messages": anthropic_msgs,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": True,
        }
        if system:
            body["system"] = system
        if tools:
            body["tools"] = _convert_tools(tools)

        headers = {
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }

        content_buf = ""
        tool_buffers: dict[str, dict] = {}

        try:
            async with _client(credentials, timeout=300) as client:
                async with client.stream(
                    "POST", f"{base_url}/v1/messages", json=body, headers=headers
                ) as resp:
                    if resp.status_code == 429:
                        raise _RateLimitError()
                    resp.raise_for_status()

                    event_type = ""
                    async for line in resp.aiter_lines():
                        if line.startswith("event: "):
                            event_type = line[7:].strip()
                            continue
                        if not line.startswith("data: "):
                            continue
                        try:
                            data = json.loads(line[6:])
                        except json.JSONDecodeError:
                            continue

                        if event_type == "content_block_delta":
                            delta = data.get("delta", {})
                            if delta.get("type") == "text_delta":
                                text = delta.get("text", "")
                                content_buf += text
                                yield {"type": "content", "text": text}
                            elif delta.get("type") == "input_json_delta":
                                idx = data.get("index", 0)
                                key = str(idx)
                                if key in tool_buffers:
                                    tool_buffers[key]["arguments"] += delta.get("partial_json", "")
                        elif event_type == "content_block_start":
                            block = data.get("content_block", {})
                            if block.get("type") == "tool_use":
                                idx = data.get("index", 0)
                                tool_buffers[str(idx)] = {
                                    "id": block.get("id", ""),
                                    "name": block.get("name", ""),
                                    "arguments": "",
                                }
        except _RateLimitError:
            raise
        except (httpx.ReadError, httpx.RemoteProtocolError, httpx.ConnectError) as e:
            logger.warning(
                "[anthropic_stream] connection interrupted: %s (content so far: %d chars)",
                e,
                len(content_buf),
            )
        except Exception as e:
            if "input stream" in str(e).lower():
                logger.warning(
                    "[anthropic_stream] input stream error after %d chars", len(content_buf)
                )
            else:
                raise

        if tool_buffers:
            parsed_tcs = []
            for key in sorted(tool_buffers, key=int):
                buf = tool_buffers[key]
                raw = buf["arguments"]
                args = {}
                if raw:
                    try:
                        args = json.loads(raw)
                    except json.JSONDecodeError:
                        pass
                parsed_tcs.append(
                    ToolCall(id=buf["id"], name=buf["name"], arguments=args, arguments_raw=raw)
                )
            yield {"type": "tool_calls", "tool_calls": [tc.__dict__ for tc in parsed_tcs]}

        yield {"type": "done", "content": content_buf}


class _RateLimitError(Exception):
    pass


def _convert_messages(messages: list[ChatMessage]) -> tuple[str, list[dict]]:
    system = ""
    out = []
    for msg in messages:
        if msg.role == "system":
            system = msg.content
        elif msg.role == "tool":
            out.append(
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": msg.tool_call_id,
                            "content": msg.content,
                        }
                    ],
                }
            )
        elif msg.role == "assistant" and msg.tool_calls:
            blocks = []
            if msg.content:
                blocks.append({"type": "text", "text": msg.content})
            for tc in msg.tool_calls:
                blocks.append(
                    {
                        "type": "tool_use",
                        "id": tc.id,
                        "name": tc.name,
                        "input": tc.arguments,
                    }
                )
            out.append({"role": "assistant", "content": blocks})
        else:
            out.append({"role": msg.role, "content": msg.content})
    return system, out


def _convert_tools(tools: list[dict]) -> list[dict]:
    result = []
    for t in tools:
        if t.get("type") == "function":
            fn = t["function"]
            result.append(
                {
                    "name": fn["name"],
                    "description": fn.get("description", ""),
                    "input_schema": fn.get("parameters", {"type": "object", "properties": {}}),
                }
            )
        else:
            result.append(t)
    return result


def _parse_response(data: dict) -> ChatResponse:
    content_text = ""
    tool_calls = []
    for block in data.get("content", []):
        if block.get("type") == "text":
            content_text += block.get("text", "")
        elif block.get("type") == "tool_use":
            raw = json.dumps(block.get("input", {}))
            tool_calls.append(
                ToolCall(
                    id=block.get("id", ""),
                    name=block.get("name", ""),
                    arguments=block.get("input", {}),
                    arguments_raw=raw,
                )
            )
    usage = data.get("usage", {})
    return ChatResponse(
        content=content_text,
        tool_calls=tool_calls or None,
        provider_id="anthropic",
        model=data.get("model", ""),
        usage={
            "prompt_tokens": usage.get("input_tokens", 0),
            "completion_tokens": usage.get("output_tokens", 0),
            "total_tokens": usage.get("input_tokens", 0) + usage.get("output_tokens", 0),
        },
        finish_reason=data.get("stop_reason", ""),
    )
