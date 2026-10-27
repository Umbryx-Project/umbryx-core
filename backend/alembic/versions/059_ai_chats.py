"""AI chat persistence tables

Revision ID: 059
Revises: 058
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "059"
down_revision = "058"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "ai_chats",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("pid", sa.String, sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.String, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("title", sa.String(255), server_default="New Chat"),
        sa.Column("provider_id", sa.String, nullable=True),
        sa.Column("model", sa.String, nullable=True),
        sa.Column("agent_mode", sa.Boolean, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_ai_chats_pid", "ai_chats", ["pid"])
    op.create_index("ix_ai_chats_user_id", "ai_chats", ["user_id"])

    op.create_table(
        "ai_messages",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("chat_id", sa.String, sa.ForeignKey("ai_chats.id", ondelete="CASCADE"), nullable=False),
        sa.Column("seq", sa.Integer, nullable=False, server_default="0"),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("content", sa.Text, server_default=""),
        sa.Column("tool_calls", JSONB, server_default="[]"),
        sa.Column("tool_call_id", sa.String, nullable=True),
        sa.Column("tool_name", sa.String, nullable=True),
        sa.Column("provider_id", sa.String, nullable=True),
        sa.Column("model", sa.String, nullable=True),
        sa.Column("usage", JSONB, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_ai_messages_chat_id", "ai_messages", ["chat_id"])

    op.create_table(
        "ai_audit_log",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("pid", sa.String, sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("chat_id", sa.String, sa.ForeignKey("ai_chats.id", ondelete="CASCADE"), nullable=True),
        sa.Column("user_id", sa.String, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("tool_name", sa.String, nullable=True),
        sa.Column("arguments", JSONB, server_default="{}"),
        sa.Column("result_summary", sa.Text, server_default=""),
        sa.Column("risk_level", sa.String(20), nullable=True),
        sa.Column("status", sa.String(20), server_default="ok"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_ai_audit_log_pid", "ai_audit_log", ["pid"])
    op.create_index("ix_ai_audit_log_chat_id", "ai_audit_log", ["chat_id"])


def downgrade() -> None:
    op.drop_table("ai_audit_log")
    op.drop_table("ai_messages")
    op.drop_table("ai_chats")
