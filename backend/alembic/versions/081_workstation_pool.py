"""Workstation pool: PlatformOps providers, user SSH keys, access grants

Revision ID: 081
Revises: 080

Product feature (2026-09-02, confirmed): pre-provision a pool of machines
through PlatformOps InfraProviders, keep users' SSH public keys on their
profiles, bind machines to users/projects by appending the user's key to
the machine's authorized_keys over SSH, revoke by removing it — every
grant/revoke lands in the project timeline and audit log.

Schema changes (all additive except two column relaxations):
- operator_workstations.user_id / .project_id → nullable (a pool machine
  has no owner/project until bound; FK actions CASCADE → SET NULL so
  deleting a project/user detaches pool machines instead of dropping them)
- operator_workstations.infra_provider_id → FK infra_providers (SET NULL)
- operator_workstations.is_pool → boolean flag
- user_ssh_keys: per-profile public keys (public material only)
- workstation_access: multi-user grant rows (workstation × user × key)

Design decisions confirmed with the product owner on 2026-09-02:
PlatformOps InfraProvider as the single provider source for new machines
(legacy cloud_credentials path stays read-compatible for existing rows);
authorized_keys managed over SSH; multi-user binding model.
"""

import sqlalchemy as sa
from alembic import op

revision = "081"
down_revision = "080"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "operator_workstations",
        sa.Column("infra_provider_id", sa.String(), nullable=True),
    )
    op.add_column(
        "operator_workstations",
        sa.Column("is_pool", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.alter_column("operator_workstations", "user_id", existing_type=sa.String(), nullable=True)
    op.alter_column(
        "operator_workstations", "project_id", existing_type=sa.String(), nullable=True
    )
    op.create_foreign_key(
        "fk_workstations_infra_provider",
        "operator_workstations",
        "infra_providers",
        ["infra_provider_id"],
        ["id"],
        ondelete="SET NULL",
    )
    # project/user FKs: CASCADE → SET NULL (pool machines survive detach)
    op.drop_constraint("operator_workstations_project_id_fkey", "operator_workstations", type_="foreignkey")
    op.create_foreign_key(
        "fk_workstations_project_setnull",
        "operator_workstations",
        "projects",
        ["project_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.drop_constraint("operator_workstations_user_id_fkey", "operator_workstations", type_="foreignkey")
    op.create_foreign_key(
        "fk_workstations_user_setnull",
        "operator_workstations",
        "users",
        ["user_id"],
        ["id"],
        ondelete="SET NULL",
    )

    op.create_table(
        "user_ssh_keys",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("user_id", sa.String(), nullable=False, index=True),
        sa.Column("name", sa.String(), nullable=False, server_default=""),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("fingerprint", sa.String(), nullable=False, server_default="", index=True),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.Column("last_used_at", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
    )
    op.create_table(
        "workstation_access",
        sa.Column("id", sa.String(), primary_key=True),
        sa.Column("workstation_id", sa.String(), nullable=False, index=True),
        sa.Column("user_id", sa.String(), nullable=False, index=True),
        sa.Column("key_id", sa.String(), nullable=False),
        sa.Column("granted_by", sa.String(), nullable=True),
        sa.Column("granted_at", sa.String(), nullable=False),
        sa.Column("revoked_at", sa.String(), nullable=True),
        sa.Column("revoked_by", sa.String(), nullable=True),
        sa.ForeignKeyConstraint(
            ["workstation_id"], ["operator_workstations.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["key_id"], ["user_ssh_keys.id"], ondelete="CASCADE"),
    )


def downgrade() -> None:
    op.drop_table("workstation_access")
    op.drop_table("user_ssh_keys")
    op.drop_constraint("fk_workstations_user_setnull", "operator_workstations", type_="foreignkey")
    op.create_foreign_key(
        "operator_workstations_user_id_fkey",
        "operator_workstations",
        "users",
        ["user_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.drop_constraint("fk_workstations_project_setnull", "operator_workstations", type_="foreignkey")
    op.create_foreign_key(
        "operator_workstations_project_id_fkey",
        "operator_workstations",
        "projects",
        ["project_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.drop_constraint("fk_workstations_infra_provider", "operator_workstations", type_="foreignkey")
    op.drop_column("operator_workstations", "is_pool")
    op.drop_column("operator_workstations", "infra_provider_id")
    op.alter_column(
        "operator_workstations", "project_id", existing_type=sa.String(), nullable=False
    )
    op.alter_column("operator_workstations", "user_id", existing_type=sa.String(), nullable=False)
