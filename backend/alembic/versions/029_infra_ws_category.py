"""add category to infra_templates + workstation_templates + remove kali from infra

Revision ID: 029
Revises: 028
"""
revision = "029"
down_revision = "028"

from alembic import op
import sqlalchemy as sa


def upgrade() -> None:
    op.add_column("infra_templates", sa.Column("category", sa.String(), nullable=False, server_default="general"))

    op.execute("UPDATE infra_templates SET category = 'c2' WHERE id LIKE '%c2%' OR id LIKE '%adaptix%'")
    op.execute("UPDATE infra_templates SET category = 'redirector' WHERE id LIKE '%redirector%'")
    op.execute("UPDATE infra_templates SET category = 'jumpbox' WHERE id LIKE '%jumpbox%'")
    op.execute("UPDATE infra_templates SET category = 'cloud_vm' WHERE kind = 'opentofu' AND category = 'general'")

    op.execute("DELETE FROM infra_templates WHERE id IN ('builtin-tooling-kali', 'builtin-k8s-kali-tooling')")

    op.add_column("workstation_templates", sa.Column("category", sa.String(), nullable=False, server_default="linux"))

    op.execute("UPDATE workstation_templates SET category = 'kali' WHERE id LIKE '%kali%'")
    op.execute("UPDATE workstation_templates SET category = 'windows' WHERE id LIKE '%commando%' OR id LIKE '%windows%'")


def downgrade() -> None:
    op.drop_column("infra_templates", "category")
    op.drop_column("workstation_templates", "category")
