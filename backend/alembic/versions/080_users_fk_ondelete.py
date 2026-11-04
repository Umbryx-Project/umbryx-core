"""Fix FKs to users.id without ON DELETE action

Revision ID: 080
Revises: 079

Security test 2026-09-02, finding 6: DELETE /api/admin/users/{uid} returned
500 whenever the user still owned rows in a table whose FK to users.id had
no ON DELETE action (Postgres treats that as RESTRICT). Classic repro: all
of the user's projects were deleted earlier (memberships cascade away with
the project), but their notifications survive — deletion then trips the
notifications FK.

Actions chosen per table semantics:
- notifications.user_id        → CASCADE  (the user's own ephemeral alerts)
- audit_log.actor_id           → SET NULL (forensic evidence survives,
                                   anonymized)
- pb_automations.owner_id      → SET NULL (automation survives, orphaned)

No data is modified — only the constraints are recreated.
"""

from alembic import op

revision = "080"
down_revision = "079"
branch_labels = None
depends_on = None


def _swap(table: str, column: str, ondelete: str) -> None:
    op.drop_constraint(f"{table}_{column}_fkey", table, type_="foreignkey")
    op.create_foreign_key(
        f"{table}_{column}_fkey_noaction",
        table,
        "users",
        [column],
        ["id"],
        ondelete=ondelete,
    )


def upgrade() -> None:
    _swap("notifications", "user_id", "CASCADE")
    _swap("audit_log", "actor_id", "SET NULL")
    _swap("pb_automations", "owner_id", "SET NULL")


def downgrade() -> None:
    for table, column in (
        ("notifications", "user_id"),
        ("audit_log", "actor_id"),
        ("pb_automations", "owner_id"),
    ):
        op.drop_constraint(f"{table}_{column}_fkey_noaction", table, type_="foreignkey")
        op.create_foreign_key(
            f"{table}_{column}_fkey",
            table,
            "users",
            [column],
            ["id"],
        )
