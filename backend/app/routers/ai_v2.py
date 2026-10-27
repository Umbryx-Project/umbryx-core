"""
AI v2 router — chat persistence, streaming, provider management, agent mode.

Endpoints:
  Provider catalog:
    GET  /api/ai/providers/types          — list registered provider types + schemas
    GET  /api/ai/providers                — list configured providers (masked)
    POST /api/ai/providers                — add provider (admin)
    PUT  /api/ai/providers/{id}           — update provider (admin)
    DELETE /api/ai/providers/{id}         — remove provider (admin)
    POST /api/ai/providers/{id}/test      — test provider connection (admin)

  Config:
    GET  /api/ai/settings                 — get AI settings
    PUT  /api/ai/settings                 — update AI settings (admin)

  Chats:
    GET  /api/projects/{pid}/ai/chats     — list chats
    POST /api/projects/{pid}/ai/chats     — create chat
    GET  /api/projects/{pid}/ai/chats/{cid} — get chat + messages
    DELETE /api/projects/{pid}/ai/chats/{cid} — delete chat

  Messaging:
    POST /api/projects/{pid}/ai/chats/{cid}/messages       — send message (non-streaming)
    POST /api/projects/{pid}/ai/chats/{cid}/stream         — send message (SSE streaming)

  Tools:
    GET  /api/ai/tools                    — list registered tools

  Audit:
    GET  /api/projects/{pid}/ai/audit     — audit log (admin)
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models
from ..core.access import check_pid_access
from ..core.ai import (
    AgentEngine,
    AIProviderRegistry,
    ChatMessage,
    CredentialStore,
    tool_registry,
)
from ..core.deps import get_current_user, require_admin
from ..database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(
    tags=["ai"],
    responses={
        403: {"description": "Forbidden"},
        500: {"description": "Internal server error"},
        503: {"description": "Service unavailable"},
    },
)


# ── Pydantic schemas ──────────────────────────────────────────────────


class ProviderCreate(BaseModel):
    id: str
    name: str = ""
    provider: str = "openai"
    model: str = ""
    base_url: str = ""
    api_key: str = ""
    enabled: bool = True
    priority: int = 999
    skip_tools: bool = False
    skip_system_prompt: bool = False
    system_prompt: str = ""


class ProviderUpdate(BaseModel):
    name: str | None = None
    provider: str | None = None
    model: str | None = None
    base_url: str | None = None
    api_key: str | None = None
    enabled: bool | None = None
    priority: int | None = None
    skip_tools: bool | None = None
    skip_system_prompt: bool | None = None
    system_prompt: str | None = None
    # Tokenize outgoing data ([IP_1]/[HOST_2]…, restored on the way back):
    # on for external APIs, pointless for local models
    anonymize: bool | None = None


class SettingsUpdate(BaseModel):
    ai_enabled: bool | None = None
    agent_mode: bool | None = None
    max_tool_calls: int | None = None
    require_confirmation_writes: bool | None = None
    block_critical_tools: bool | None = None


class ChatCreate(BaseModel):
    title: str | None = None
    provider_id: str | None = None
    model: str | None = None
    agent_mode: bool = True
    agent_id: str | None = None


class AgentCreate(BaseModel):
    name: str
    description: str = ""
    system_prompt: str
    agent_mode: bool = True
    allowed_tools: list[str] | None = None
    suggestions: list[str] = []


class MessageSend(BaseModel):
    message: str
    agent_mode: bool | None = None
    confirmed_tools: list[dict] = []


def _chat_allowed_tools(db: Session, chat: models.AIChat) -> list[str] | None:
    """Tool allowlist for the chat's agent persona (None = full registry)."""
    if not chat or not chat.agent_id:
        return None
    from ..core.ai.agents import get_agent

    persona = get_agent(db, chat.agent_id)
    if not persona:
        return None
    allowed = persona.get("allowed_tools")
    return [t for t in allowed if t] if isinstance(allowed, list) else None


# ── Helpers ───────────────────────────────────────────────────────────


def _build_system_prompt(db: Session, pid: str, custom_prompt: str = "") -> str:
    host_count = db.query(models.Host).filter(models.Host.pid == pid).count()
    cred_count = db.query(models.Cred).filter(models.Cred.pid == pid).count()
    finding_count = db.query(models.Finding).filter(models.Finding.pid == pid).count()
    open_finding_count = (
        db.query(models.Finding)
        .filter(models.Finding.pid == pid, models.Finding.status == "open")
        .count()
    )
    today = datetime.now(UTC).strftime("%Y-%m-%d")
    project_stats = (
        f"Current project has: {host_count} hosts, {cred_count} credentials, "
        f"{finding_count} findings ({open_finding_count} open).\n"
        f"Today: {today}"
    )

    from ..core.ai.tool_playbook import build_tool_playbook
    from ..core.ai.tool_registry import tool_registry

    playbook = build_tool_playbook(set(tool_registry.list_names()))

    if custom_prompt and custom_prompt.strip():
        return f"{custom_prompt.strip()}\n\n{project_stats}\n\n{playbook}"

    return (
        "You are an autonomous AI security assistant embedded in Umbryx, "
        "a penetration testing platform.\n"
        f"{project_stats}\n"
        "You have tools to read and modify project data, create findings, "
        "run playbooks, and launch scans.\n"
        "Be concise, technical, and focus on actionable security insights.\n"
        "You are operating in an authorized penetration testing environment.\n"
        f"\n{playbook}\n"
    )


def _msg_to_dict(m: models.AIMessage) -> dict:
    return {
        "id": m.id,
        "seq": m.seq,
        "role": m.role,
        "content": m.content,
        "tool_calls": m.tool_calls or [],
        "tool_call_id": m.tool_call_id,
        "tool_name": m.tool_name,
        "provider_id": m.provider_id,
        "model": m.model,
        "usage": m.usage or {},
        "created_at": m.created_at.isoformat() if m.created_at else None,
    }


def _chat_to_dict(c: models.AIChat, message_count: int = 0) -> dict:
    return {
        "id": c.id,
        "pid": c.pid,
        "title": c.title,
        "provider_id": c.provider_id,
        "model": c.model,
        "agent_mode": c.agent_mode,
        "agent_id": c.agent_id,
        "message_count": message_count,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "updated_at": c.updated_at.isoformat() if c.updated_at else None,
    }


def _check_ai_enabled(store: CredentialStore):
    cfg = store.get_config()
    if not cfg.get("ai_enabled", True):
        raise HTTPException(503, "AI is disabled by the administrator")


# ── Status ────────────────────────────────────────────────────────────


@router.get("/api/ai/agents")
def list_ai_agents(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    from ..core.ai.agents import list_agents

    return {"agents": list_agents(db)}


@router.post("/api/ai/agents", status_code=201)
def create_ai_agent(
    body: AgentCreate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    from ..core.enums import UserRole

    if user.role != UserRole.PLATFORM_ADMIN:
        raise HTTPException(403, "Only platform admins can create agents")
    from ..core.ai.agents import save_custom_agent

    return save_custom_agent(db, body.model_dump(), user.id)


@router.delete("/api/ai/agents/{agent_id}", status_code=204)
def delete_ai_agent(
    agent_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    from ..core.enums import UserRole

    if user.role != UserRole.PLATFORM_ADMIN:
        raise HTTPException(403, "Only platform admins can delete agents")
    from ..core.ai.agents import delete_custom_agent

    if not delete_custom_agent(db, agent_id):
        raise HTTPException(404, "No custom agent with this id")
    return None


@router.get("/api/ai/status")
def get_ai_status(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)] = None,
):
    """Lightweight flag for the frontend to gate AI UI elements."""
    store = CredentialStore(db)
    cfg = store.get_config()
    has_providers = bool(cfg.get("providers", []))
    if not has_providers:
        from ..core.ai_manager import get_config as get_legacy_config

        legacy_cfg = get_legacy_config(db)
        has_providers = bool(legacy_cfg.get("providers", []))
    return {
        "enabled": cfg.get("ai_enabled", True),
        "has_providers": has_providers,
    }


# ── Provider catalog ──────────────────────────────────────────────────


@router.get("/api/ai/providers/types")
def list_provider_types(
    user: Annotated[models.User, Depends(get_current_user)],
):
    return CredentialStore.get_provider_types()


@router.get("/api/ai/providers")
def list_providers(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    store = CredentialStore(db)
    return {"providers": store.list_providers(mask=True)}


@router.post("/api/ai/providers/migrate")
def migrate_legacy(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(require_admin)],
):
    store = CredentialStore(db)
    count = store.migrate_from_legacy()
    return {"migrated": count, "providers": store.list_providers(mask=True)}


@router.post("/api/ai/providers")
def add_provider(
    body: ProviderCreate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(require_admin)],
):
    store = CredentialStore(db)
    existing = store.get_provider(body.id, decrypt=False)
    if existing:
        raise HTTPException(409, f"Provider '{body.id}' already exists")
    if not AIProviderRegistry.has(body.provider):
        raise HTTPException(400, f"Unknown provider type: {body.provider}")
    return store.add_provider(body.model_dump())


@router.put("/api/ai/providers/{provider_id}")
def update_provider(
    provider_id: str,
    body: ProviderUpdate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(require_admin)],
):
    store = CredentialStore(db)
    result = store.update_provider(provider_id, body.model_dump(exclude_none=True))
    if not result:
        raise HTTPException(404, "Provider not found")
    return result


@router.delete("/api/ai/providers/{provider_id}")
def remove_provider(
    provider_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(require_admin)],
):
    store = CredentialStore(db)
    if not store.remove_provider(provider_id):
        raise HTTPException(404, "Provider not found")
    return {"ok": True}


@router.post("/api/ai/providers/{provider_id}/test")
async def test_provider(
    provider_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(require_admin)],
):
    store = CredentialStore(db)
    provider_cfg = store.get_provider(provider_id, decrypt=True)
    if not provider_cfg:
        raise HTTPException(404, "Provider not found")
    ptype = provider_cfg.get("provider", "openai")
    provider = AIProviderRegistry.get(ptype)
    if not provider:
        raise HTTPException(400, f"No adapter for type: {ptype}")
    creds = {k: v for k, v in provider_cfg.items() if k in ("api_key", "base_url")}
    result = await provider.connect(creds)
    return result


@router.post("/api/ai/providers/{provider_id}/models")
async def list_provider_models(
    provider_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(require_admin)],
):
    store = CredentialStore(db)
    provider_cfg = store.get_provider(provider_id, decrypt=True)
    if not provider_cfg:
        raise HTTPException(404, "Provider not found")
    ptype = provider_cfg.get("provider", "openai")
    provider = AIProviderRegistry.get(ptype)
    if not provider:
        raise HTTPException(400, f"No adapter for type: {ptype}")
    creds = {k: v for k, v in provider_cfg.items() if k in ("api_key", "base_url")}
    try:
        models_list = await provider.list_models(creds)
        return {"models": models_list}
    except Exception as e:
        return {"models": [], "error": str(e)}


class FetchModelsRequest(BaseModel):
    provider: str = "openai"
    base_url: str = ""
    api_key: str = ""


@router.post("/api/ai/providers/fetch-models")
async def fetch_models(
    body: FetchModelsRequest,
    user: Annotated[models.User, Depends(require_admin)],
):
    """Fetch available models from a provider without saving it.

    Used by the admin UI to auto-populate the model dropdown
    when configuring a new provider.
    """
    provider = AIProviderRegistry.get(body.provider)
    if not provider:
        raise HTTPException(400, f"Unknown provider type: {body.provider}")
    creds = {"api_key": body.api_key, "base_url": body.base_url}
    try:
        models_list = await provider.list_models(creds)
        return {"models": models_list}
    except Exception as e:
        return {"models": [], "error": str(e)}


# ── Settings ──────────────────────────────────────────────────────────


@router.get("/api/ai/settings")
def get_ai_settings(
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    store = CredentialStore(db)
    # Security audit 2026-10-09 (M-6): get_config() returned the raw
    # providers[] — for legacy rows that means plaintext api_keys to any
    # authenticated user. /api/ai/providers exists masked for exactly this
    # reason; reuse the same masking here.
    cfg = store.get_config()
    cfg["providers"] = store.list_providers(mask=True)
    return cfg


@router.put("/api/ai/settings")
def update_ai_settings(
    body: SettingsUpdate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(require_admin)],
):
    store = CredentialStore(db)
    return store.save_config(body.model_dump(exclude_none=True))


# ── Chats ─────────────────────────────────────────────────────────────


@router.get("/api/projects/{pid}/ai/chats")
def list_chats(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "findings.read")
    q = (
        db.query(models.AIChat)
        .filter(models.AIChat.pid == pid)
        .order_by(models.AIChat.updated_at.desc())
    )
    chats = q.all()
    result = []
    for c in chats:
        count = db.query(models.AIMessage).filter(models.AIMessage.chat_id == c.id).count()
        result.append(_chat_to_dict(c, count))
    return {"chats": result}


@router.post("/api/projects/{pid}/ai/chats")
def create_chat(
    pid: str,
    body: ChatCreate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "findings.read")
    from ..core.utils import new_id

    agent_cfg = None
    if body.agent_id:
        from ..core.ai.agents import get_agent

        agent_cfg = get_agent(db, body.agent_id)
        if not agent_cfg:
            raise HTTPException(404, f"Unknown agent: {body.agent_id}")

    chat = models.AIChat(
        id=new_id("ai_chat"),
        pid=pid,
        user_id=user.id,
        title=body.title or (agent_cfg["name"] if agent_cfg else "New Chat"),
        provider_id=body.provider_id,
        model=body.model,
        agent_mode=body.agent_mode if body.agent_mode is not None else bool(
            agent_cfg.get("agent_mode", True)
        ) if agent_cfg else True,
        agent_id=body.agent_id,
    )
    db.add(chat)
    db.commit()
    db.refresh(chat)
    return _chat_to_dict(chat)


@router.get("/api/projects/{pid}/ai/chats/{cid}")
def get_chat(
    pid: str,
    cid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "findings.read")
    chat = db.query(models.AIChat).filter(models.AIChat.id == cid, models.AIChat.pid == pid).first()
    if not chat:
        raise HTTPException(404, "Chat not found")
    messages = (
        db.query(models.AIMessage)
        .filter(models.AIMessage.chat_id == cid)
        .order_by(models.AIMessage.seq)
        .all()
    )
    result = _chat_to_dict(chat, len(messages))
    result["messages"] = [_msg_to_dict(m) for m in messages]
    return result


@router.delete("/api/projects/{pid}/ai/chats/{cid}")
def delete_chat(
    pid: str,
    cid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "findings.read")
    chat = db.query(models.AIChat).filter(models.AIChat.id == cid, models.AIChat.pid == pid).first()
    if not chat:
        raise HTTPException(404, "Chat not found")
    db.delete(chat)
    db.commit()
    return {"ok": True}


# ── Messaging (non-streaming) ─────────────────────────────────────────


@router.post("/api/projects/{pid}/ai/chats/{cid}/messages")
async def send_message(
    pid: str,
    cid: str,
    body: MessageSend,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "findings.read")

    store = CredentialStore(db)
    _check_ai_enabled(store)

    chat = db.query(models.AIChat).filter(models.AIChat.id == cid, models.AIChat.pid == pid).first()
    if not chat:
        raise HTTPException(404, "Chat not found")

    # Extract scalar values before any commits — SQLAlchemy expires all
    # objects on commit, making subsequent attribute access fail with
    # "Instance is not bound to a Session".
    user_id = user.id
    chat_agent_mode = chat.agent_mode
    chat_title = chat.title

    from ..core.utils import new_id

    user_msg = models.AIMessage(
        id=new_id("ai_msg"),
        chat_id=cid,
        seq=_next_seq(db, cid),
        role="user",
        content=body.message,
    )
    db.add(user_msg)
    db.commit()

    history = _load_history(db, cid, body.message, pid)
    agent_mode = body.agent_mode if body.agent_mode is not None else chat_agent_mode
    allowed_tools = _chat_allowed_tools(db, chat)
    agent = AgentEngine(db)
    result = await agent.run(
        messages=history,
        pid=pid,
        chat_id=cid,
        user_id=user_id,
        agent_mode=agent_mode,
        confirmed_tools=body.confirmed_tools,
        allowed_tools=allowed_tools,
    )

    assistant_msg = models.AIMessage(
        id=new_id("ai_msg"),
        chat_id=cid,
        seq=_next_seq(db, cid),
        role="assistant",
        content=result.content,
        provider_id=result.provider_id,
        usage={},
    )
    db.add(assistant_msg)

    if chat_title == "New Chat" and body.message:
        db.query(models.AIChat).filter(models.AIChat.id == cid).update({"title": body.message[:60]})

    db.commit()

    return {
        "answer": result.content,
        "provider_id": result.provider_id,
        "steps": [s.__dict__ for s in result.steps],
        "confirmed": result.confirmed,
        "tool_calls_made": result.tool_calls_made,
    }


# ── Messaging (streaming SSE) ─────────────────────────────────────────


@router.post("/api/projects/{pid}/ai/chats/{cid}/stream")
async def stream_message(
    pid: str,
    cid: str,
    body: MessageSend,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "findings.read")

    store = CredentialStore(db)
    _check_ai_enabled(store)

    chat = db.query(models.AIChat).filter(models.AIChat.id == cid, models.AIChat.pid == pid).first()
    if not chat:
        raise HTTPException(404, "Chat not found")

    # Extract scalar values before any commits.
    user_id = user.id
    chat_agent_mode = chat.agent_mode
    chat_title = chat.title

    from ..core.utils import new_id

    user_msg = models.AIMessage(
        id=new_id("ai_msg"),
        chat_id=cid,
        seq=_next_seq(db, cid),
        role="user",
        content=body.message,
    )
    db.add(user_msg)
    db.commit()

    history = _load_history(db, cid, body.message, pid)
    agent_mode = body.agent_mode if body.agent_mode is not None else chat_agent_mode
    agent = AgentEngine(db)

    content_buf = ""
    provider_id_captured = ""

    async def event_stream():
        nonlocal content_buf, provider_id_captured
        try:
            async for event in agent.run_stream(
                messages=history,
                pid=pid,
                chat_id=cid,
                user_id=user_id,
                agent_mode=agent_mode,
                confirmed_tools=body.confirmed_tools,
                allowed_tools=_chat_allowed_tools(db, chat),
            ):
                etype = event.get("type")
                if etype == "content":
                    content_buf += event["text"]
                if etype == "done":
                    provider_id_captured = event.get("provider_id", "")
                yield f"data: {json.dumps(event)}\n\n"
                if etype in ("done", "confirmation_needed", "error"):
                    break
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"

        try:
            assistant_msg = models.AIMessage(
                id=new_id("ai_msg"),
                chat_id=cid,
                seq=_next_seq(db, cid),
                role="assistant",
                content=content_buf,
                provider_id=provider_id_captured,
            )
            db.add(assistant_msg)
            if chat_title == "New Chat" and body.message:
                db.query(models.AIChat).filter(models.AIChat.id == cid).update(
                    {"title": body.message[:60]}
                )
            db.commit()
        except Exception as e:
            logger.warning("[ai_stream] failed to persist assistant message: %s", e)

    return StreamingResponse(event_stream(), media_type="text/event-stream")


# ── Tools ─────────────────────────────────────────────────────────────


@router.get("/api/ai/tools")
def list_tools(
    user: Annotated[models.User, Depends(get_current_user)],
):
    return {"tools": tool_registry.to_dict_list()}


# ── Audit log ─────────────────────────────────────────────────────────


@router.get("/api/projects/{pid}/ai/audit")
def get_audit_log(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
    limit: int = Query(100),
    offset: int = Query(0),
):
    check_pid_access(db, pid, user, "findings.read")
    entries = (
        db.query(models.AIAuditLog)
        .filter(models.AIAuditLog.pid == pid)
        .order_by(models.AIAuditLog.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return {
        "entries": [
            {
                "id": e.id,
                "chat_id": e.chat_id,
                "action": e.action,
                "tool_name": e.tool_name,
                "arguments": e.arguments,
                "result_summary": e.result_summary,
                "risk_level": e.risk_level,
                "status": e.status,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in entries
        ]
    }


def _chat_allowed_tools(db: Session, chat: models.AIChat) -> list[str] | None:
    """Tool allowlist for the chat's agent persona (None = full registry)."""
    if not chat or not chat.agent_id:
        return None
    from ..core.ai.agents import get_agent

    persona = get_agent(db, chat.agent_id)
    if not persona:
        return None
    allowed = persona.get("allowed_tools")
    return [t for t in allowed if t] if isinstance(allowed, list) else None


# ── Helpers ───────────────────────────────────────────────────────────


def _next_seq(db: Session, chat_id: str) -> int:
    last = (
        db.query(models.AIMessage)
        .filter(models.AIMessage.chat_id == chat_id)
        .order_by(models.AIMessage.seq.desc())
        .first()
    )
    return (last.seq + 1) if last else 1


def _load_history(
    db: Session,
    chat_id: str,
    current_message: str,
    pid: str,
) -> list[ChatMessage]:
    """Build message list for the LLM from chat history."""
    store = CredentialStore(db)
    next_p = store.get_next_provider()
    custom_prompt = next_p.get("system_prompt", "") if next_p else ""
    skip_sys = next_p.get("skip_system_prompt", False) if next_p else False

    # Agent persona: its system prompt wins over the provider-level custom
    # prompt — the persona IS the chat's contract.
    chat = db.query(models.AIChat).filter(models.AIChat.id == chat_id).first()
    persona = None
    if chat and chat.agent_id:
        from ..core.ai.agents import get_agent

        persona = get_agent(db, chat.agent_id)
    if persona:
        custom_prompt = persona["system_prompt"]
        skip_sys = False

    messages: list[ChatMessage] = []
    if not skip_sys:
        messages.append(
            ChatMessage(role="system", content=_build_system_prompt(db, pid, custom_prompt))
        )

    prior = (
        db.query(models.AIMessage)
        .filter(models.AIMessage.chat_id == chat_id)
        .order_by(models.AIMessage.seq)
        .all()
    )

    for m in prior:
        if m.role == "system":
            continue
        msg = ChatMessage(
            role=m.role,
            content=m.content,
            tool_calls=None,
            tool_call_id=m.tool_call_id or "",
            name=m.tool_name or "",
        )
        if m.tool_calls:
            from ..core.ai.provider import ToolCall as TC

            msg.tool_calls = [
                TC(
                    id=tc.get("id", ""),
                    name=tc.get("name", ""),
                    arguments=tc.get("arguments", {}),
                    arguments_raw=tc.get("arguments_raw", ""),
                )
                for tc in m.tool_calls
            ]
        messages.append(msg)

    messages.append(ChatMessage(role="user", content=current_message))
    return messages
