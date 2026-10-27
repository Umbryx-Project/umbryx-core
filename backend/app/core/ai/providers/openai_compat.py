"""
OpenAI-compatible provider adapter.

Works with: OpenAI, Groq, Mistral, OpenRouter, LiteLLM, vLLM, llama.cpp server,
and any other endpoint that implements ``/v1/chat/completions``.
"""

from __future__ import annotations

import json
import logging
import re
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

_DEFAULT_BASE_URL = "https://api.openai.com"
_DEFAULT_MODELS = ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"]


def _client(credentials: dict, **kw) -> httpx.AsyncClient:
    """Egress factory: proxy-pool rule "ai" + ai_provider:{id} target."""
    from ...net import egress_async_client

    return egress_async_client("ai", f"ai_provider:{credentials.get('id', '')}", **kw)


@AIProviderRegistry.register("openai")

class OpenAICompatProvider(AIProvider):

    @staticmethod
    def get_type() -> str:
        return "openai"

    @staticmethod
    def get_display_name() -> str:
        return "OpenAI"

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
                "api_key", "API Key", "password", required=True, help_text="OpenAI API key (sk-...)"
            ),
            CredentialField(
                "base_url",
                "Base URL",
                "text",
                required=False,
                default="https://api.openai.com",
                placeholder="https://api.openai.com",
                help_text="Override for OpenAI-compatible endpoints (Groq, Mistral, vLLM, etc.)",
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
                headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
                resp = await client.get(f"{base_url}/v1/models", headers=headers)
                if resp.status_code == 401:
                    return {"ok": False, "message": "Invalid API key"}
                if resp.status_code != 200:
                    return {"ok": False, "message": f"HTTP {resp.status_code}"}
                return {"ok": True, "message": "Connected"}
        except httpx.ConnectError:
            return {"ok": False, "message": "Connection refused"}
        except Exception as e:
            return {"ok": False, "message": str(e)}

    async def list_models(self, credentials: dict) -> list[dict]:
        base_url = credentials.get("base_url", "").rstrip("/") or _DEFAULT_BASE_URL
        api_key = credentials.get("api_key", "")
        async with _client(credentials, timeout=15) as client:
            headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
            resp = await client.get(f"{base_url}/v1/models", headers=headers)
            resp.raise_for_status()
            data = resp.json()
            models = []
            for m in data.get("data", []):
                models.append({"id": m.get("id", ""), "name": m.get("id", "")})
            return models

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

        body: dict[str, Any] = {
            "model": model,
            "messages": [m.to_openai_dict() for m in messages],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if tools:
            body["tools"] = tools

        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        async with _client(credentials,
            timeout=httpx.Timeout(300.0, connect=15.0),
            limits=httpx.Limits(max_keepalive_connections=5),
        ) as client:
            resp = await client.post(f"{base_url}/v1/chat/completions", json=body, headers=headers)
            if resp.status_code == 429:
                raise _RateLimitError()
            resp.raise_for_status()
            return _parse_response(resp.json(), "openai")

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

        body: dict[str, Any] = {
            "model": model,
            "messages": [m.to_openai_dict() for m in messages],
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": True,
        }
        if tools:
            body["tools"] = tools

        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        content_buf = ""
        tool_calls_buf: dict[int, dict] = {}

        try:
            async with _client(credentials, timeout=300) as client:
                async with client.stream(
                    "POST", f"{base_url}/v1/chat/completions", json=body, headers=headers
                ) as resp:
                    if resp.status_code == 429:
                        raise _RateLimitError()
                    resp.raise_for_status()

                    async for line in resp.aiter_lines():
                        if not line.startswith("data: "):
                            continue
                        data_str = line[6:]
                        if data_str.strip() == "[DONE]":
                            break
                        try:
                            chunk = json.loads(data_str)
                        except json.JSONDecodeError:
                            continue
                        delta = chunk.get("choices", [{}])[0].get("delta", {})
                        reasoning = delta.get("reasoning_content") or delta.get("reasoning")
                        if reasoning:
                            yield {"type": "reasoning", "text": reasoning}
                        if "content" in delta and delta["content"]:
                            content_buf += delta["content"]
                            yield {"type": "content", "text": delta["content"]}
                        for tc in delta.get("tool_calls", []):
                            idx = tc.get("index", 0)
                            if idx not in tool_calls_buf:
                                tool_calls_buf[idx] = {
                                    "id": tc.get("id", ""),
                                    "name": tc.get("function", {}).get("name", ""),
                                    "arguments": "",
                                }
                            else:
                                if tc.get("id"):
                                    tool_calls_buf[idx]["id"] = tc["id"]
                                if tc.get("function", {}).get("name"):
                                    tool_calls_buf[idx]["name"] = tc["function"]["name"]
                            tool_calls_buf[idx]["arguments"] += tc.get("function", {}).get(
                                "arguments", ""
                            )
        except _RateLimitError:
            raise
        except (httpx.ReadError, httpx.RemoteProtocolError, httpx.ConnectError) as e:
            logger.warning(
                "[openai_stream] connection interrupted: %s (content so far: %d chars)",
                e,
                len(content_buf),
            )
        except Exception as e:
            if "input stream" in str(e).lower():
                logger.warning(
                    "[openai_stream] input stream error after %d chars", len(content_buf)
                )
            else:
                raise

        if tool_calls_buf:
            parsed_tcs = []
            for idx in sorted(tool_calls_buf):
                raw = tool_calls_buf[idx]["arguments"]
                args = {}
                if raw:
                    try:
                        args = json.loads(raw)
                    except json.JSONDecodeError:
                        pass
                parsed_tcs.append(
                    ToolCall(
                        id=tool_calls_buf[idx]["id"],
                        name=tool_calls_buf[idx]["name"],
                        arguments=args,
                        arguments_raw=raw,
                    )
                )
            yield {"type": "tool_calls", "tool_calls": [tc.__dict__ for tc in parsed_tcs]}

        yield {"type": "done", "content": content_buf}


class _RateLimitError(Exception):
    pass


def _parse_response(data: dict, provider_id: str) -> ChatResponse:
    choices = data.get("choices", [])
    if not choices:
        return ChatResponse(provider_id=provider_id)
    choice = choices[0]
    msg = choice.get("message", {})
    content = msg.get("content") or ""
    content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()

    tool_calls = []
    for tc in msg.get("tool_calls") or []:
        fn = tc.get("function", {})
        raw_args = fn.get("arguments", "{}")
        args = {}
        if raw_args:
            try:
                args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
            except (json.JSONDecodeError, TypeError):
                pass
        tool_calls.append(
            ToolCall(
                id=tc.get("id", ""),
                name=fn.get("name", ""),
                arguments=args,
                arguments_raw=raw_args if isinstance(raw_args, str) else json.dumps(raw_args),
            )
        )

    usage = data.get("usage", {})
    return ChatResponse(
        content=content,
        tool_calls=tool_calls or None,
        provider_id=provider_id,
        model=data.get("model", ""),
        usage={
            "prompt_tokens": usage.get("prompt_tokens", 0),
            "completion_tokens": usage.get("completion_tokens", 0),
            "total_tokens": usage.get("total_tokens", 0),
        },
        finish_reason=choice.get("finish_reason", ""),
    )


# ── OpenAI-compatible aliases ─────────────────────────────────────────
# These are distinct provider types that share the same OpenAI wire format
# but have different default URLs, models, and display names.


@AIProviderRegistry.register("litellm")
class LiteLLMProvider(OpenAICompatProvider):
    """LiteLLM proxy — OpenAI-compatible gateway to 100+ LLM providers."""

    @staticmethod
    def get_type() -> str:
        return "litellm"

    @staticmethod
    def get_display_name() -> str:
        return "LiteLLM (Proxy)"

    @staticmethod
    def get_category() -> str:
        return "proxy"

    @staticmethod
    def get_default_models() -> list[str]:
        return []

    @staticmethod
    def get_credentials_schema() -> list[CredentialField]:
        return [
            CredentialField(
                "base_url",
                "Base URL",
                "text",
                required=True,
                default="http://localhost:4000",
                placeholder="http://localhost:4000",
                help_text="LiteLLM proxy server URL",
            ),
            CredentialField(
                "api_key",
                "API Key (optional)",
                "password",
                required=False,
                default="",
                help_text="LiteLLM master key (if configured)",
            ),
        ]


@AIProviderRegistry.register("groq")
class GroqProvider(OpenAICompatProvider):

    _DEFAULT_BASE_URL_GROQ = "https://api.groq.com/openai"

    @staticmethod
    def get_type() -> str:
        return "groq"

    @staticmethod
    def get_display_name() -> str:
        return "Groq"

    @staticmethod
    def get_category() -> str:
        return "cloud"

    @staticmethod
    def get_default_models() -> list[str]:
        return ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768"]

    @staticmethod
    def get_credentials_schema() -> list[CredentialField]:
        return [
            CredentialField(
                "api_key", "API Key", "password", required=True, help_text="Groq API key"
            ),
            CredentialField(
                "base_url",
                "Base URL",
                "text",
                required=False,
                default="https://api.groq.com/openai",
            ),
        ]


@AIProviderRegistry.register("mistral")
class MistralProvider(OpenAICompatProvider):

    @staticmethod
    def get_type() -> str:
        return "mistral"

    @staticmethod
    def get_display_name() -> str:
        return "Mistral AI"

    @staticmethod
    def get_category() -> str:
        return "cloud"

    @staticmethod
    def get_default_models() -> list[str]:
        return ["mistral-large-latest", "mistral-small", "codestral-latest"]

    @staticmethod
    def get_credentials_schema() -> list[CredentialField]:
        return [
            CredentialField(
                "api_key", "API Key", "password", required=True, help_text="Mistral API key"
            ),
            CredentialField(
                "base_url",
                "Base URL",
                "text",
                required=False,
                default="https://api.mistral.ai",
            ),
        ]


@AIProviderRegistry.register("openrouter")
class OpenRouterProvider(OpenAICompatProvider):

    @staticmethod
    def get_type() -> str:
        return "openrouter"

    @staticmethod
    def get_display_name() -> str:
        return "OpenRouter"

    @staticmethod
    def get_category() -> str:
        return "cloud"

    @staticmethod
    def get_default_models() -> list[str]:
        return ["openai/gpt-4o-mini", "anthropic/claude-3.5-sonnet", "google/gemini-flash-1.5"]

    @staticmethod
    def get_credentials_schema() -> list[CredentialField]:
        return [
            CredentialField(
                "api_key", "API Key", "password", required=True, help_text="OpenRouter API key"
            ),
            CredentialField(
                "base_url",
                "Base URL",
                "text",
                required=False,
                default="https://openrouter.ai/api",
            ),
        ]
