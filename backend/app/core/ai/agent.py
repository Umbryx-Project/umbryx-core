"""
Agent engine — multi-step LLM execution loop with tool calling,
risk classification, confirmation, and audit logging.

The loop:
  1. Send messages + tools to LLM
  2. If response has no tool_calls → return content
  3. For each tool_call:
     a. Look up risk level
     b. If critical + block_critical_tools → skip with error
     c. If write + require_confirmation → yield confirmation request
     d. Execute tool → append result message
  4. Repeat until no tool_calls or max_steps reached
  5. Final call without tools for summary
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from ..utils import new_id
from .credential_store import CredentialStore
from .provider import AIProviderRegistry, ChatMessage, ToolCall
from .tool_registry import RiskLevel, tool_registry

logger = logging.getLogger(__name__)


@dataclass
class AgentStep:
    """One step in the agent execution loop."""

    step_num: int
    type: str  # llm_call | tool_call | tool_result | confirmation_needed | error | done
    content: str = ""
    tool_name: str = ""
    tool_args: dict = field(default_factory=dict)
    tool_result: dict | None = None
    risk: str = ""
    provider_id: str = ""
    usage: dict = field(default_factory=dict)


@dataclass
class AgentResult:
    """Final result of the agent loop."""

    content: str
    steps: list[AgentStep] = field(default_factory=list)
    provider_id: str = ""
    tool_calls_made: int = 0
    confirmed: bool = True


def _provider_wants_anonymize(cfg: dict) -> bool:
    """Per-provider switch for outgoing data tokenization.

    Default ON (opt-out): identifiers must not leave the perimeter unless
    an admin explicitly trusts the endpoint (a fully local Ollama/vLLM
    box) and disables it per provider. Found live: providers created
    before the field existed carried real engagement data verbatim.
    """
    return cfg.get("anonymize", True)


class AgentEngine:
    """Orchestrates the multi-step agent loop with safety controls."""

    def __init__(self, db: Session):
        self.db = db
        self.cred_store = CredentialStore(db)
        self.config = self.cred_store.get_config()

    async def run(
        self,
        messages: list[ChatMessage],
        pid: str,
        chat_id: str | None = None,
        user_id: str | None = None,
        max_steps: int | None = None,
        agent_mode: bool | None = None,
        confirmed_tools: list[dict] | None = None,
        allowed_tools: list[str] | None = None,
    ) -> AgentResult:
        """Run the full agent loop. Returns final result with all steps."""
        steps: list[AgentStep] = []
        max_steps = max_steps or self.config.get("max_tool_calls", 10)
        agent_mode = agent_mode if agent_mode is not None else self.config.get("agent_mode", True)
        block_critical = self.config.get("block_critical_tools", True)
        require_confirm = self.config.get("require_confirmation_writes", True)

        confirmed_set = set()
        if confirmed_tools:
            for ct in confirmed_tools:
                confirmed_set.add(
                    (ct.get("name", ""), json.dumps(ct.get("arguments", {}), sort_keys=True))
                )

        tools_openai = (
            tool_registry.to_openai(include_critical=False, allowed=allowed_tools)
            if agent_mode
            else None
        )
        tried_providers: set[str] = set()
        provider_id = ""
        step_num = 0
        # One token map per run — created lazily when a provider opts in,
        # then reused so tokens stay stable across iterations.
        anonymizer = None
        if any(_provider_wants_anonymize(p) for p in self.cred_store.list_providers()):
            from .anonymizer import Anonymizer

            anonymizer = Anonymizer()
        tool_call_count = 0
        last_provider_error = ""

        while True:
            step_num += 1
            provider_cfg = self.cred_store.get_next_provider(skip_ids=tried_providers)
            if not provider_cfg:
                if tried_providers:
                    # Surface WHY the providers failed — "connection drops" in the
                    # UI gave no hint the LLM gateway itself was 500-ing.
                    detail = f" Last error: {last_provider_error}" if last_provider_error else ""
                    steps.append(
                        AgentStep(
                            step_num=step_num,
                            type="error",
                            content=f"All AI providers are unavailable or rate limited.{detail}",
                        )
                    )
                    return AgentResult(
                        content=f"All AI providers are unavailable or rate limited.{detail}",
                        steps=steps,
                        provider_id=provider_id,
                    )
                steps.append(
                    AgentStep(
                        step_num=step_num,
                        type="error",
                        content="No AI providers configured",
                    )
                )
                return AgentResult(content="No AI providers configured.", steps=steps)

            provider_id = provider_cfg["id"]
            ptype = provider_cfg.get("provider", "openai")
            provider = AIProviderRegistry.get(ptype)
            if not provider:
                tried_providers.add(provider_id)
                continue

            creds = {k: v for k, v in provider_cfg.items() if k in ("api_key", "base_url")}
            model = provider_cfg.get("model", "")
            use_tools = tools_openai if not provider_cfg.get("skip_tools") else None

            # Outgoing data tokenization (per-provider opt-in): the model
            # sees [IP_1]/[HOST_2]…, real values never leave the perimeter.
            out_messages = anonymizer.anonymize_messages(messages) if anonymizer else messages

            step = AgentStep(step_num=step_num, type="llm_call", provider_id=provider_id)
            steps.append(step)

            try:
                resp = await provider.chat(
                    messages=out_messages,
                    credentials=creds,
                    model=model,
                    tools=use_tools if tool_call_count < max_steps else None,
                )
                if anonymizer:
                    resp.content = anonymizer.restore(resp.content)
                    for tc in resp.tool_calls or []:
                        tc.arguments = anonymizer.restore_args(tc.arguments)
            except Exception as e:
                if "429" in str(e) or "RateLimit" in type(e).__name__:
                    self.cred_store.mark_429(provider_id)
                tried_providers.add(provider_id)
                step.type = "error"
                step.content = f"Provider {provider_id} error: {e}"
                last_provider_error = f"{provider_id}: {e}"
                logger.warning("[agent] provider %s error: %s", provider_id, e)
                continue

            self._audit(
                chat_id,
                pid,
                user_id,
                "provider_call",
                tool_name=model,
                result_summary=resp.content[:200],
                status="ok",
            )

            step.usage = resp.usage
            step.content = resp.content[:200] if resp.content else ""

            if not resp.has_tool_calls or not agent_mode or tool_call_count >= max_steps:
                messages.append(
                    ChatMessage(role="assistant", content=resp.content, tool_calls=resp.tool_calls)
                )
                steps.append(
                    AgentStep(
                        step_num=step_num,
                        type="done",
                        content=resp.content,
                        provider_id=provider_id,
                        usage=resp.usage,
                    )
                )
                return AgentResult(
                    content=resp.content,
                    steps=steps,
                    provider_id=provider_id,
                    tool_calls_made=tool_call_count,
                )

            messages.append(
                ChatMessage(role="assistant", content=resp.content, tool_calls=resp.tool_calls)
            )

            for tc in resp.tool_calls:
                tool_call_count += 1
                td = tool_registry.get(tc.name)

                if td is None:
                    result = {"error": f"Unknown tool: {tc.name}"}
                    step_t = AgentStep(
                        step_num=step_num,
                        type="tool_result",
                        tool_name=tc.name,
                        tool_args=tc.arguments,
                        tool_result=result,
                        risk="unknown",
                    )
                    steps.append(step_t)
                    messages.append(
                        ChatMessage(
                            role="tool",
                            content=json.dumps(result),
                            tool_call_id=tc.id,
                            name=tc.name,
                        )
                    )
                    continue

                risk = td.risk
                if risk == RiskLevel.CRITICAL and block_critical:
                    result = {
                        "error": f"Tool '{tc.name}' is classified as critical and is blocked by safety policy."
                    }
                    self._audit(
                        chat_id,
                        pid,
                        user_id,
                        "blocked",
                        tool_name=tc.name,
                        arguments=tc.arguments,
                        risk_level="critical",
                        result_summary=result["error"],
                        status="blocked",
                    )
                    steps.append(
                        AgentStep(
                            step_num=step_num,
                            type="tool_result",
                            tool_name=tc.name,
                            tool_args=tc.arguments,
                            tool_result=result,
                            risk="critical",
                        )
                    )
                    messages.append(
                        ChatMessage(
                            role="tool",
                            content=json.dumps(result),
                            tool_call_id=tc.id,
                            name=tc.name,
                        )
                    )
                    continue

                if risk == RiskLevel.WRITE and require_confirm:
                    key = (tc.name, json.dumps(tc.arguments, sort_keys=True))
                    if key not in confirmed_set:
                        steps.append(
                            AgentStep(
                                step_num=step_num,
                                type="confirmation_needed",
                                tool_name=tc.name,
                                tool_args=tc.arguments,
                                risk="write",
                            )
                        )
                        return AgentResult(
                            content=f"Confirmation required for tool: {tc.name}",
                            steps=steps,
                            provider_id=provider_id,
                            tool_calls_made=tool_call_count,
                            confirmed=False,
                        )

                steps.append(
                    AgentStep(
                        step_num=step_num,
                        type="tool_call",
                        tool_name=tc.name,
                        tool_args=tc.arguments,
                        risk=risk.value,
                    )
                )

                result = await tool_registry.execute(
                    self.db, pid, tc.name, tc.arguments, user_id=user_id
                )

                result_str = json.dumps(result) if not isinstance(result, str) else result
                self._audit(
                    chat_id,
                    pid,
                    user_id,
                    "tool_call",
                    tool_name=tc.name,
                    arguments=tc.arguments,
                    risk_level=risk.value,
                    result_summary=result_str[:300],
                    status="ok",
                )

                steps.append(
                    AgentStep(
                        step_num=step_num,
                        type="tool_result",
                        tool_name=tc.name,
                        tool_args=tc.arguments,
                        tool_result=result,
                        risk=risk.value,
                    )
                )
                messages.append(
                    ChatMessage(
                        role="tool",
                        content=result_str[:4000],
                        tool_call_id=tc.id,
                        name=tc.name,
                    )
                )

            tried_providers.clear()

    async def run_stream(
        self,
        messages: list[ChatMessage],
        pid: str,
        chat_id: str | None = None,
        user_id: str | None = None,
        max_steps: int | None = None,
        agent_mode: bool | None = None,
        confirmed_tools: list[dict] | None = None,
        allowed_tools: list[str] | None = None,
    ) -> AsyncIterator[dict]:
        """Streaming version of the agent loop. Yields SSE events."""
        max_steps = max_steps or self.config.get("max_tool_calls", 10)
        agent_mode = agent_mode if agent_mode is not None else self.config.get("agent_mode", True)
        block_critical = self.config.get("block_critical_tools", True)
        require_confirm = self.config.get("require_confirmation_writes", True)

        confirmed_set = set()
        if confirmed_tools:
            for ct in confirmed_tools:
                confirmed_set.add(
                    (ct.get("name", ""), json.dumps(ct.get("arguments", {}), sort_keys=True))
                )

        tools_openai = (
            tool_registry.to_openai(include_critical=False, allowed=allowed_tools)
            if agent_mode
            else None
        )
        tried_providers: set[str] = set()
        tool_call_count = 0
        step_num = 0
        last_provider_error = ""
        # One token map for the whole stream (see run()).
        anonymizer = None
        if any(_provider_wants_anonymize(p) for p in self.cred_store.list_providers()):
            from .anonymizer import Anonymizer

            anonymizer = Anonymizer()

        while True:
            step_num += 1
            provider_cfg = self.cred_store.get_next_provider(skip_ids=tried_providers)
            if not provider_cfg:
                detail = f" Last error: {last_provider_error}" if last_provider_error else ""
                yield {
                    "type": "error",
                    "message": (
                        "No AI providers available"
                        if not tried_providers
                        else "All AI providers failed"
                    )
                    + detail,
                }
                return

            provider_id = provider_cfg["id"]
            ptype = provider_cfg.get("provider", "openai")
            provider = AIProviderRegistry.get(ptype)
            if not provider:
                tried_providers.add(provider_id)
                continue

            creds = {k: v for k, v in provider_cfg.items() if k in ("api_key", "base_url")}
            model = provider_cfg.get("model", "")
            use_tools = tools_openai if not provider_cfg.get("skip_tools") else None
            use_tools = use_tools if tool_call_count < max_steps else None

            content_buf = ""
            collected_tool_calls: list[ToolCall] = []

            out_messages = anonymizer.anonymize_messages(messages) if anonymizer else messages

            yield {"type": "step", "step_num": step_num, "provider_id": provider_id}

            try:
                async for event in provider.chat_stream(
                    messages=out_messages,
                    credentials=creds,
                    model=model,
                    tools=use_tools,
                ):
                    etype = event.get("type")
                    if etype == "reasoning":
                        if anonymizer:
                            event = {**event, "text": anonymizer.restore(event.get("text", ""))}
                        yield event
                    elif etype == "content":
                        content_buf += event["text"]
                        if anonymizer:
                            yield {
                                "type": "content",
                                "text": anonymizer.restore_stream_chunk(event["text"]),
                            }
                        else:
                            yield {"type": "content", "text": event["text"]}
                    elif etype == "tool_calls":
                        for tc_dict in event.get("tool_calls", []):
                            collected_tool_calls.append(
                                ToolCall(
                                    id=tc_dict.get("id", ""),
                                    name=tc_dict.get("name", ""),
                                    arguments=tc_dict.get("arguments", {}),
                                    arguments_raw=tc_dict.get("arguments_raw", ""),
                                )
                            )
                    elif etype == "done":
                        usage = event.get("usage", {})
                        self._audit(
                            chat_id,
                            pid,
                            user_id,
                            "provider_call",
                            tool_name=model,
                            result_summary=content_buf[:200],
                            status="ok",
                        )
                        yield {"type": "usage", "usage": usage}
            except Exception as e:
                if "429" in str(e) or "RateLimit" in type(e).__name__:
                    self.cred_store.mark_429(provider_id)
                tried_providers.add(provider_id)
                last_provider_error = f"{provider_id}: {e}"
                yield {"type": "error", "message": f"Provider error: {e}"}
                continue

            if not collected_tool_calls or not agent_mode or tool_call_count >= max_steps:
                if anonymizer:
                    content_buf = anonymizer.restore(content_buf)
                messages.append(
                    ChatMessage(
                        role="assistant",
                        content=content_buf,
                        tool_calls=collected_tool_calls or None,
                    )
                )
                yield {
                    "type": "done",
                    "content": content_buf,
                    "provider_id": provider_id,
                    "tool_calls_made": tool_call_count,
                }
                return

            if anonymizer:
                content_buf = anonymizer.restore(content_buf)
                for tc in collected_tool_calls:
                    tc.arguments = anonymizer.restore_args(tc.arguments)
            messages.append(
                ChatMessage(
                    role="assistant",
                    content=content_buf,
                    tool_calls=collected_tool_calls,
                )
            )

            for tc in collected_tool_calls:
                tool_call_count += 1
                td = tool_registry.get(tc.name)

                if td is None:
                    result = {"error": f"Unknown tool: {tc.name}"}
                    yield {
                        "type": "tool_result",
                        "tool_name": tc.name,
                        "arguments": tc.arguments,
                        "result": result,
                    }
                    messages.append(
                        ChatMessage(
                            role="tool",
                            content=json.dumps(result),
                            tool_call_id=tc.id,
                            name=tc.name,
                        )
                    )
                    continue

                risk = td.risk
                if risk == RiskLevel.CRITICAL and block_critical:
                    result = {
                        "error": f"Tool '{tc.name}' blocked by safety policy (critical risk)."
                    }
                    self._audit(
                        chat_id,
                        pid,
                        user_id,
                        "blocked",
                        tool_name=tc.name,
                        arguments=tc.arguments,
                        risk_level="critical",
                        result_summary=result["error"],
                        status="blocked",
                    )
                    yield {
                        "type": "tool_result",
                        "tool_name": tc.name,
                        "arguments": tc.arguments,
                        "result": result,
                        "blocked": True,
                    }
                    messages.append(
                        ChatMessage(
                            role="tool",
                            content=json.dumps(result),
                            tool_call_id=tc.id,
                            name=tc.name,
                        )
                    )
                    continue

                if risk == RiskLevel.WRITE and require_confirm:
                    key = (tc.name, json.dumps(tc.arguments, sort_keys=True))
                    if key not in confirmed_set:
                        yield {
                            "type": "confirmation_needed",
                            "tool_name": tc.name,
                            "arguments": tc.arguments,
                            "risk": risk.value,
                        }
                        return

                yield {
                    "type": "tool_call",
                    "tool_name": tc.name,
                    "arguments": tc.arguments,
                    "risk": risk.value,
                }

                result = await tool_registry.execute(
                    self.db, pid, tc.name, tc.arguments, user_id=user_id
                )
                result_str = json.dumps(result) if not isinstance(result, str) else result
                self._audit(
                    chat_id,
                    pid,
                    user_id,
                    "tool_call",
                    tool_name=tc.name,
                    arguments=tc.arguments,
                    risk_level=risk.value,
                    result_summary=result_str[:300],
                    status="ok",
                )

                yield {
                    "type": "tool_result",
                    "tool_name": tc.name,
                    "arguments": tc.arguments,
                    "result": result,
                }

                messages.append(
                    ChatMessage(
                        role="tool",
                        content=result_str[:4000],
                        tool_call_id=tc.id,
                        name=tc.name,
                    )
                )

            tried_providers.clear()

    def _audit(
        self,
        chat_id: str | None,
        pid: str,
        user_id: str | None,
        action: str,
        tool_name: str = "",
        arguments: dict | None = None,
        risk_level: str = "",
        result_summary: str = "",
        status: str = "ok",
        provider_id: str = "",
        usage: dict | None = None,
    ):
        """Write to AI audit log."""
        try:
            from ...models import AIAuditLog

            log = AIAuditLog(
                id=new_id("ai_aud"),
                pid=pid,
                chat_id=chat_id,
                user_id=user_id,
                action=action,
                tool_name=tool_name,
                arguments=arguments or {},
                result_summary=result_summary,
                risk_level=risk_level,
                status=status,
            )
            self.db.add(log)
            self.db.commit()
        except Exception as e:
            logger.warning("[agent] failed to write audit log: %s", e)
            self.db.rollback()
