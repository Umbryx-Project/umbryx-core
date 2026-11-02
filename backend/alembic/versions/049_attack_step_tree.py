"""attack_step tree structure — parent_step_id, confidence, branch_name"""

from alembic import op
import sqlalchemy as sa

revision = "049"
down_revision = "048"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("attack_steps", sa.Column("parent_step_id", sa.String(), nullable=True))
    op.add_column("attack_steps", sa.Column("confidence", sa.String(), nullable=True, server_default="medium"))
    op.add_column("attack_steps", sa.Column("branch_name", sa.String(), nullable=True))
    op.create_index("ix_attack_steps_parent", "attack_steps", ["parent_step_id"])
    op.create_foreign_key(
        "fk_attack_steps_parent",
        "attack_steps",
        "attack_steps",
        ["parent_step_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("fk_attack_steps_parent", "attack_steps", type_="foreignkey")
    op.drop_index("ix_attack_steps_parent")
    op.drop_column("attack_steps", "branch_name")
    op.drop_column("attack_steps", "confidence")
    op.drop_column("attack_steps", "parent_step_id")
