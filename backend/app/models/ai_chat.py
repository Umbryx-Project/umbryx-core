"""
AI Chat persistence models.

Tables:
  - ai_chats: conversation sessions scoped to project + user
  - ai_messages: individual messages (user/assistant/tool) with tool call data
  - ai_audit_log: agent actions for security audit trail
"""

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import relationship

from ..database import Base


class AIChat(Base):
    __tablename__ = "ai_chats"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = Column(String, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    title = Column(String(255), default="New Chat")
    provider_id = Column(String, nullable=True)
    model = Column(String, nullable=True)
    agent_mode = Column(Boolean, default=True)
    agent_id = Column(String, nullable=True)  # persona from the ai_agents catalog
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())

    messages = relationship(
        "AIMessage", back_populates="chat", cascade="all, delete-orphan", order_by="AIMessage.seq"
    )


class AIMessage(Base):
    __tablename__ = "ai_messages"

    id = Column(String, primary_key=True)
    chat_id = Column(
        String, ForeignKey("ai_chats.id", ondelete="CASCADE"), nullable=False, index=True
    )
    seq = Column(Integer, nullable=False, default=0)
    role = Column(String(20), nullable=False)  # system | user | assistant | tool
    content = Column(Text, default="")
    tool_calls = Column(JSONB, default=list)  # [{id, name, arguments}]
    tool_call_id = Column(String, nullable=True)
    tool_name = Column(String, nullable=True)
    provider_id = Column(String, nullable=True)
    model = Column(String, nullable=True)
    usage = Column(JSONB, default=dict)  # {prompt_tokens, completion_tokens}
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    chat = relationship("AIChat", back_populates="messages")


class AIAuditLog(Base):
    __tablename__ = "ai_audit_log"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    chat_id = Column(
        String, ForeignKey("ai_chats.id", ondelete="CASCADE"), nullable=True, index=True
    )
    user_id = Column(String, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action = Column(
        String(100), nullable=False
    )  # tool_call | provider_call | confirmation | blocked
    tool_name = Column(String, nullable=True)
    arguments = Column(JSONB, default=dict)
    result_summary = Column(Text, default="")
    risk_level = Column(String(20), nullable=True)  # read | write | critical
    status = Column(String(20), default="ok")  # ok | blocked | confirmed | denied | error
    created_at = Column(DateTime(timezone=True), server_default=func.now())
