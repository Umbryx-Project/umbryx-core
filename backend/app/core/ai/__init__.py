"""
AI Integration — provider abstraction, tool registry, agent engine, and chat persistence.

This package supercedes the flat ``ai_manager.py`` / ``ai_tools.py`` modules with
a pluggable architecture mirroring the infra CloudProvider / DeployMethod pattern.
"""

from .agent import AgentEngine, AgentResult, AgentStep
from .credential_store import CredentialStore
from .provider import (
    AIProvider,
    AIProviderRegistry,
    ChatMessage,
    ChatResponse,
    CredentialField,
    ProviderInfo,
    ToolCall,
)
from .tool_registry import RiskLevel, ToolDef, ToolRegistry, tool_registry

__all__ = [
    "AIProvider",
    "AIProviderRegistry",
    "ChatMessage",
    "ChatResponse",
    "ToolCall",
    "CredentialField",
    "ProviderInfo",
    "ToolRegistry",
    "ToolDef",
    "tool_registry",
    "RiskLevel",
    "AgentEngine",
    "AgentStep",
    "AgentResult",
    "CredentialStore",
]
