"""infra_providers: add deploy fields (host, port, ssh_user, ssh_key, kubeconfig, deploy_mode); stack_services: node_id → provider_id + deploy_mode

Revision ID: 056
Revises: 055
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "056"
down_revision = "055"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("infra_providers", sa.Column("host", sa.String, nullable=True))
    op.add_column("infra_providers", sa.Column("port", sa.Integer, nullable=False, server_default="22"))
    op.add_column("infra_providers", sa.Column("ssh_user", sa.String, nullable=False, server_default="root"))
    op.add_column("infra_providers", sa.Column("ssh_key", sa.Text, nullable=True))
    op.add_column("infra_providers", sa.Column("kubeconfig", sa.Text, nullable=True))
    op.add_column("infra_providers", sa.Column("deploy_mode", sa.String, nullable=False, server_default="ssh"))

    op.add_column("infra_stack_services", sa.Column("provider_id", sa.String, nullable=True))
    op.add_column("infra_stack_services", sa.Column("deploy_mode", sa.String, nullable=False, server_default="ssh"))

    op.execute(
        "UPDATE infra_stack_services SET provider_id = node_id WHERE node_id IS NOT NULL"
    )

    op.drop_constraint("infra_stack_services_node_id_fkey", "infra_stack_services", type_="foreignkey")
    op.drop_column("infra_stack_services", "node_id")

    op.create_foreign_key(
        "infra_stack_services_provider_id_fkey",
        "infra_stack_services", "infra_providers",
        ["provider_id"], ["id"], ondelete="SET NULL",
    )

    op.execute(
        "UPDATE infra_providers SET host = connection->>'host', "
        "ssh_user = COALESCE(connection->>'username', 'root'), "
        "ssh_key = connection->>'ssh_key', "
        "kubeconfig = connection->>'kube_config', "
        "deploy_mode = CASE WHEN type IN ('kubernetes','k3s','docker','docker-compose','swarm','nomad','podman') THEN 'k8s' ELSE 'ssh' END "
        "WHERE host IS NULL AND connection IS NOT NULL"
    )


def downgrade() -> None:
    op.add_column("infra_stack_services", sa.Column("node_id", sa.String, nullable=True))
    op.execute("UPDATE infra_stack_services SET node_id = provider_id")
    op.drop_constraint("infra_stack_services_provider_id_fkey", "infra_stack_services", type_="foreignkey")
    op.drop_column("infra_stack_services", "deploy_mode")
    op.drop_column("infra_stack_services", "provider_id")

    op.drop_column("infra_providers", "deploy_mode")
    op.drop_column("infra_providers", "kubeconfig")
    op.drop_column("infra_providers", "ssh_key")
    op.drop_column("infra_providers", "ssh_user")
    op.drop_column("infra_providers", "port")
    op.drop_column("infra_providers", "host")
