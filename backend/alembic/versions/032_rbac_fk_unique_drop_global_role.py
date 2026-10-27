"""RBAC hardening: FK+UNIQUE on org/team/member tables, drop global_role, cleanup team: source rows

Revision ID: 032
Revises: 031
"""
revision = "032"
down_revision = "031"

from alembic import op
import sqlalchemy as sa


def upgrade() -> None:
    # ── Cleanup orphan rows before adding FKs ──────────────────────────
    # OrganizationMembers with missing org or user
    op.execute(
        "DELETE FROM organization_members WHERE org_id NOT IN (SELECT id FROM organizations)"
    )
    op.execute(
        "DELETE FROM organization_members WHERE user_id NOT IN (SELECT id FROM users)"
    )

    # Teams with missing org
    op.execute(
        "DELETE FROM team_members WHERE team_id IN (SELECT id FROM teams WHERE org_id NOT IN (SELECT id FROM organizations))"
    )
    op.execute(
        "DELETE FROM teams WHERE org_id NOT IN (SELECT id FROM organizations)"
    )

    # TeamMembers with missing team or user
    op.execute(
        "DELETE FROM team_members WHERE team_id NOT IN (SELECT id FROM teams)"
    )
    op.execute(
        "DELETE FROM team_members WHERE user_id NOT IN (SELECT id FROM users)"
    )

    # ── Deduplicate before adding UNIQUE constraints ────────────────────
    op.execute(
        """
        DELETE FROM organization_members a USING organization_members b
        WHERE a.id < b.id AND a.org_id = b.org_id AND a.user_id = b.user_id
        """
    )
    op.execute(
        """
        DELETE FROM team_members a USING team_members b
        WHERE a.id < b.id AND a.team_id = b.team_id AND a.user_id = b.user_id
        """
    )

    # ── Remove materialized team-sourced project members ────────────────
    op.execute(
        "DELETE FROM project_members WHERE source LIKE 'team:%'"
    )

    # ── FK on teams.org_id ──────────────────────────────────────────────
    op.create_foreign_key(
        "fk_teams_org_id", "teams", "organizations",
        ["org_id"], ["id"], ondelete="CASCADE",
    )

    # ── FKs on organization_members ─────────────────────────────────────
    op.create_foreign_key(
        "fk_org_members_org_id", "organization_members", "organizations",
        ["org_id"], ["id"], ondelete="CASCADE",
    )
    op.create_foreign_key(
        "fk_org_members_user_id", "organization_members", "users",
        ["user_id"], ["id"], ondelete="CASCADE",
    )
    op.create_unique_constraint(
        "uq_org_member", "organization_members", ["org_id", "user_id"],
    )

    # ── FKs on team_members ─────────────────────────────────────────────
    op.create_foreign_key(
        "fk_team_members_team_id", "team_members", "teams",
        ["team_id"], ["id"], ondelete="CASCADE",
    )
    op.create_foreign_key(
        "fk_team_members_user_id", "team_members", "users",
        ["user_id"], ["id"], ondelete="CASCADE",
    )
    op.create_unique_constraint(
        "uq_team_member", "team_members", ["team_id", "user_id"],
    )

    # ── Drop global_role column from users ──────────────────────────────
    op.drop_column("users", "global_role")


def downgrade() -> None:
    op.add_column("users", sa.Column("global_role", sa.String(), nullable=False, server_default="regular"))

    op.drop_constraint("uq_team_member", "team_members", type_="unique")
    op.drop_constraint("fk_team_members_user_id", "team_members", type_="foreignkey")
    op.drop_constraint("fk_team_members_team_id", "team_members", type_="foreignkey")

    op.drop_constraint("uq_org_member", "organization_members", type_="unique")
    op.drop_constraint("fk_org_members_user_id", "organization_members", type_="foreignkey")
    op.drop_constraint("fk_org_members_org_id", "organization_members", type_="foreignkey")

    op.drop_constraint("fk_teams_org_id", "teams", type_="foreignkey")
