"""ai_chats: per-chat agent persona

Revision ID: 087
Revises: 086

AI chats gain an agent_id pointing into the ai_agents catalog
(GlobalSetting). The agent pins the chat's system prompt and restricts
the tool allowlist passed to AgentEngine — the capability boundary lives
in ToolRegistry.to_openai(allowed=...), not in the prompt.
"""

import sqlalchemy as sa
from alembic import op

revision = "087"
down_revision = "086"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("ai_chats", sa.Column("agent_id", sa.String(), nullable=True))


def downgrade() -> None:
    op.drop_column("ai_chats", "agent_id")
