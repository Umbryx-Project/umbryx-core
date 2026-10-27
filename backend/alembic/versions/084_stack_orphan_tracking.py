"""infra_stacks: track stacks orphaned by project deletion

Revision ID: 084
Revises: 083

DELETE /api/projects/{pid} used to rely on the DB-level
ondelete="SET NULL" of infra_stacks.project_id: bound stacks silently
became standalone while their cloud resources kept running — invisible
cost, forgotten attack infrastructure (documented as a known gap in
ARCHITECTURE.md §2 "Teardown isolation").

Project deletion now stamps such stacks before the project row goes
away: mode flips to "standalone", binding fields are cleared, and
detached_at / detached_from_project record why the stack is unbound.
The stacks list exposes ?orphaned=true to surface them; binding the
stack to a new project clears the stamps.
"""

import sqlalchemy as sa
from alembic import op

revision = "084"
down_revision = "083"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("infra_stacks", sa.Column("detached_at", sa.String(), nullable=True))
    op.add_column(
        "infra_stacks", sa.Column("detached_from_project", sa.String(), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("infra_stacks", "detached_from_project")
    op.drop_column("infra_stacks", "detached_at")
