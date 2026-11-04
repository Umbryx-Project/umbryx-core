"""Fix JSONB columns, add FK constraints on pid columns, add missing indexes.

Revision ID: 043
Revises: 042
"""
from alembic import op
import sqlalchemy as sa

revision = "043"
down_revision = "042"


def upgrade():
    conn = op.get_bind()
    dialect = conn.dialect.name

    if dialect == "postgresql":
        for table, col in [
            ("clusters", "meta"),
            ("attack_path_nodes", "position"),
            ("attack_path_versions", "snapshot"),
            ("metric_snapshots", "dims"),
            ("conflict_records", "local_payload"),
            ("conflict_records", "remote_payload"),
        ]:
            conn.execute(sa.text(
                f'ALTER TABLE "{table}" ALTER COLUMN "{col}" DROP DEFAULT'
            ))
            conn.execute(sa.text(
                f'ALTER TABLE "{table}" ALTER COLUMN "{col}" TYPE JSON USING "{col}"::json'
            ))
            conn.execute(sa.text(
                f'ALTER TABLE "{table}" ALTER COLUMN "{col}" SET DEFAULT \'{{}}\'::json'
            ))

    for table, col in [
        ("attack_path_nodes", "pid"),
        ("attack_path_edges", "pid"),
        ("attack_path_branches", "pid"),
        ("entity_links", "pid"),
        ("metric_snapshots", "pid"),
    ]:
        try:
            op.create_foreign_key(f"fk_{table}_pid", table, "projects", [col], ["id"], ondelete="CASCADE")
        except Exception:
            pass

    for table, cols in [
        ("tasks", ["pid", "status", "assignee"]),
        ("remediations", ["pid", "finding_id"]),
        ("evidence", ["pid"]),
        ("identities", ["pid"]),
        ("attack_path_nodes", ["host_id", "deleted_at"]),
        ("attack_path_branches", ["root_node", "parent_branch_id", "deleted_at"]),
        ("entity_links", ["deleted_at"]),
        ("tasks", ["deleted_at"]),
        ("remediations", ["deleted_at"]),
        ("identities", ["deleted_at"]),
        ("sync_state", ["pid"]),
        ("sync_events", ["pid"]),
    ]:
        for c in cols:
            try:
                op.create_index(f"ix_{table}_{c}", table, [c])
            except Exception:
                pass


def downgrade():
    pass
