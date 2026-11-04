"""
AI Provider abstraction layer.

Each provider (OpenAI, Anthropic, Ollama, etc.) implements the same interface
so that new providers can be added without touching agent/engine code.

Usage::

    @AIProviderRegistry.register("openai")
    class OpenAIProvider(AIProvider):
        @staticmethod
        def get_credentials_schema() -> list[CredentialField]:
            return [CredentialField("api_key", "API Key", "password")]
        def chat(self, messages, model, tools=None, **kwargs) -> ChatResponse:
            ...
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


class CredentialField:
    """Describes one field in a provider's credential/settings form."""

    __slots__ = (
        "name",
        "label",
        "type",
        "required",
        "default",
        "placeholder",
        "options",
        "help_text",
        "secret",
    )

    def __init__(
        self,
        name: str,
        label: str,
        type: str = "text",
        required: bool = True,
        default: str = "",
        placeholder: str = "",
        options: list[dict] | None = None,
        help_text: str = "",
        secret: bool = False,
    ):
        self.name = name
        self.label = label
        self.type = type
        self.required = required
        self.default = default
        self.placeholder = placeholder
        self.options = options or []
        self.help_text = help_text
        self.secret = secret or type == "password"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "label": self.label,
            "type": self.type,
            "required": self.required,
            "default": self.default,
            "placeholder": self.placeholder,
            "options": self.options,
            "help_text": self.help_text,
            "secret": self.secret,
        }


@dataclass
class ChatMessage:
    """Unified message format used across all providers."""

    role: str  # system | user | assistant | tool
    content: str = ""
    tool_calls: list[ToolCall] | None = None
    tool_call_id: str = ""
    name: str = ""  # tool name for role=tool

    def to_openai_dict(self) -> dict:
        d: dict[str, Any] = {"role": self.role, "content": self.content}
        if self.tool_calls:
            d["tool_calls"] = [
                tc.to_openai_dict() if hasattr(tc, "to_openai_dict") else dict(tc)
                for tc in self.tool_calls
            ]
        if self.tool_call_id:
            d["tool_call_id"] = self.tool_call_id
        if self.name:
            d["name"] = self.name
        return d


@dataclass
class ToolCall:
    """A single tool/function call requested by the LLM."""

    id: str = ""
    name: str = ""
    arguments: dict = field(default_factory=dict)
    arguments_raw: str = ""  # original JSON string from provider

    def to_openai_dict(self) -> dict:
        return {
            "id": self.id,
            "type": "function",
            "function": {
                "name": self.name,
                "arguments": self.arguments_raw or _safe_json_dumps(self.arguments),
            },
        }


@dataclass
class ChatResponse:
    """Unified response from any provider's chat call."""

    content: str = ""
    tool_calls: list[ToolCall] = None
    provider_id: str = ""
    model: str = ""
    usage: dict = field(default_factory=dict)  # {prompt_tokens, completion_tokens, total_tokens}
    finish_reason: str = ""

    @property
    def has_tool_calls(self) -> bool:
        return bool(self.tool_calls)


@dataclass
class ProviderInfo:
    """Metadata about a registered provider type."""

    type: str
    display_name: str
    category: str  # cloud | local | proxy
    supports_tools: bool = True
    supports_streaming: bool = True
    default_models: list[str] = field(default_factory=list)
    credentials_schema: list[dict] = field(default_factory=list)


def _safe_json_dumps(obj) -> str:
    import json

    try:
        return json.dumps(obj)
    except (TypeError, ValueError):
        return "{}"


class AIProvider(ABC):
    """Base interface for all AI providers.

    Subclasses encapsulate provider-specific HTTP logic behind a uniform
    interface.  Each provider declares its capabilities (tool support,
    streaming) and credential schema.
    """

    @staticmethod
    @abstractmethod
    def get_type() -> str:
        """Unique provider type id (e.g. 'openai', 'anthropic', 'ollama')."""
        ...

    @staticmethod
    @abstractmethod
    def get_display_name() -> str: ...

    @staticmethod
    @abstractmethod
    def get_category() -> str:
        """cloud | local | proxy."""
        ...

    @staticmethod
    @abstractmethod
    def get_credentials_schema() -> list[CredentialField]: ...

    @staticmethod
    def supports_tools() -> bool:
        return True

    @staticmethod
    def supports_streaming() -> bool:
        return True

    @staticmethod
    def get_default_models() -> list[str]:
        return []

    @staticmethod
    def estimate_tokens(text: str) -> int:
        """Rough token estimate (~4 chars per token)."""
        return max(1, len(text) // 4)

    @abstractmethod
    async def connect(self, credentials: dict) -> dict:
        """Validate connection. Returns {ok: bool, message: str}."""
        ...

    @abstractmethod
    async def list_models(self, credentials: dict) -> list[dict]:
        """List available models. Returns [{id, name, ...}]."""
        ...

    @abstractmethod
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
        """Send a chat completion request. Returns unified ChatResponse."""
        ...

    async def chat_stream(
        self,
        messages: list[ChatMessage],
        credentials: dict,
        model: str,
        tools: list[dict] | None = None,
        temperature: float = 0.7,
        max_tokens: int = 4096,
        **kwargs,
    ) -> AsyncIterator[dict]:
        """Stream chat tokens as SSE-style dicts.

        Default implementation falls back to non-streaming chat,
        yielding the full response as a single chunk.
        Override for true streaming.
        """
        resp = await self.chat(
            messages, credentials, model, tools, temperature, max_tokens, **kwargs
        )
        yield {"type": "content", "text": resp.content}
        if resp.tool_calls:
            yield {"type": "tool_calls", "tool_calls": [tc.__dict__ for tc in resp.tool_calls]}
        yield {"type": "done", "usage": resp.usage, "finish_reason": resp.finish_reason}


class AIProviderRegistry:
    """Registry for AI provider adapters.

    Providers self-register via decorator::

        @AIProviderRegistry.register("openai")
        class OpenAIProvider(AIProvider): ...
    """

    _providers: dict[str, type[AIProvider]] = {}
    _instances: dict[str, AIProvider] = {}

    @classmethod
    def register(cls, provider_type: str):
        def decorator(provider_cls: type[AIProvider]):
            cls._providers[provider_type] = provider_cls
            logger.debug("AI provider registered: %s -> %s", provider_type, provider_cls.__name__)
            return provider_cls

        return decorator

    @classmethod
    def get(cls, provider_type: str) -> AIProvider | None:
        if provider_type in cls._instances:
            return cls._instances[provider_type]
        provider_cls = cls._providers.get(provider_type)
        if not provider_cls:
            return None
        instance = provider_cls()
        cls._instances[provider_type] = instance
        return instance

    @classmethod
    def list_types(cls) -> list[str]:
        return sorted(cls._providers.keys())

    @classmethod
    def list_infos(cls) -> list[ProviderInfo]:
        result = []
        for ptype, pcls in cls._providers.items():
            result.append(
                ProviderInfo(
                    type=ptype,
                    display_name=pcls.get_display_name(),
                    category=pcls.get_category(),
                    supports_tools=pcls.supports_tools(),
                    supports_streaming=pcls.supports_streaming(),
                    default_models=pcls.get_default_models(),
                    credentials_schema=[f.to_dict() for f in pcls.get_credentials_schema()],
                )
            )
        return result

    @classmethod
    def get_schema(cls, provider_type: str) -> list[dict]:
        provider_cls = cls._providers.get(provider_type)
        if not provider_cls:
            return []
        return [f.to_dict() for f in provider_cls.get_credentials_schema()]

    @classmethod
    def has(cls, provider_type: str) -> bool:
        return provider_type in cls._providers


def _import_builtin_providers():
    from .providers import anthropic, ollama, openai_compat  # noqa: F401


_import_builtin_providers()
