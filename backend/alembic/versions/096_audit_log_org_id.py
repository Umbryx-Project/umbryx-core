"""audit_log: org_id column for per-tier retention (ФТ-3)

Revision ID: 096
Revises: 095

org_id used to exist only inside the free-text `detail` blob for
org-level audit entries (member/team actions), and not at all for
project-scoped entries — there was no queryable way to say "all audit
entries for org X" without parsing JSON strings. Backfills existing rows
best-effort from projects.org_id for project-scoped entries; org-level
entries predating this migration keep org_id NULL (their org_id is only
recoverable from the detail JSON, which isn't worth a data migration for
audit history — new entries are correct going forward).
"""

import sqlalchemy as sa
from alembic import op

revision = "096"
down_revision = "095"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "audit_log",
        sa.Column(
            "org_id",
            sa.String(),
            sa.ForeignKey("organizations.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_audit_org_ts", "audit_log", ["org_id", "ts"])
    op.execute(
        """
        UPDATE audit_log
        SET org_id = projects.org_id
        FROM projects
        WHERE audit_log.project_id = projects.id
          AND audit_log.org_id IS NULL
        """
    )


def downgrade() -> None:
    op.drop_index("ix_audit_org_ts", table_name="audit_log")
    op.drop_column("audit_log", "org_id")
