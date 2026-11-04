"""core_objects.project_id FK + IOC tracker project scoping

Revision ID: 078
Revises: 077

Audit 2026-08-31, finding 4.1.5: CoreObject.project_id had no FK and the
IOC tracker never set it — every IOC was readable/writable by any
authenticated user. This migration adds the referential constraint
(ON DELETE CASCADE, matching every other project-scoped entity).

The column stays NULLABLE on purpose: modules_api's platform-global objects
(project_id IS NULL, admin-only mutation) are a supported feature covered by
test_modules_api_objects_authz.py. The IOC tracker itself now always writes
a concrete project_id — pre-existing IOC rows without a project cannot be
attributed to any project, so they are deleted here (data-breaking change,
marked ⚠ DATA in CHANGELOG).

Reversal: drops the FK; does not resurrect deleted rows.
"""

from alembic import op

revision = "078"
down_revision = "077"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("DELETE FROM core_objects WHERE project_id IS NULL AND type = 'ioc'")
    op.create_foreign_key(
        "fk_core_objects_project_id",
        "core_objects",
        "projects",
        ["project_id"],
        ["id"],
        ondelete="CASCADE",
    )


def downgrade() -> None:
    op.drop_constraint("fk_core_objects_project_id", "core_objects", type_="foreignkey")
