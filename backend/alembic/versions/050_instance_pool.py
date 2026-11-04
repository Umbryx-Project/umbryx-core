"""instance pool: templates, managed instances, credentials"""

revision = "050"
down_revision = "049"
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa

from app.models._types import JSONB


def upgrade() -> None:
    op.create_table(
        "instance_templates",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("name", sa.String, nullable=False),
        sa.Column("service_type", sa.String, nullable=False, server_default="custom"),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("manifest", JSONB, nullable=False, server_default="{}"),
        sa.Column("config_template", JSONB, nullable=False, server_default="{}"),
        sa.Column("config_schema", JSONB, nullable=False, server_default="{}"),
        sa.Column("default_replicas", sa.Integer, nullable=False, server_default="1"),
        sa.Column("resource_limits", JSONB, nullable=False, server_default="{}"),
        sa.Column("ports", JSONB, nullable=False, server_default="[]"),
        sa.Column("health_check_path", sa.String, nullable=True),
        sa.Column("min_pool_size", sa.Integer, nullable=False, server_default="0"),
        sa.Column("org_id", sa.String, sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True),
        sa.Column("created_by", sa.String, nullable=True),
        sa.Column("ts", sa.String, nullable=False),
    )

    op.create_table(
        "managed_instances",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("template_id", sa.String, sa.ForeignKey("instance_templates.id", ondelete="SET NULL"), nullable=True),
        sa.Column("status", sa.String, nullable=False, server_default="provisioning"),
        sa.Column("project_id", sa.String, sa.ForeignKey("projects.id", ondelete="SET NULL"), nullable=True),
        sa.Column("namespace", sa.String, nullable=False),
        sa.Column("deployment_name", sa.String, nullable=False),
        sa.Column("configmap_name", sa.String, nullable=False),
        sa.Column("service_name", sa.String, nullable=True),
        sa.Column("config_current", JSONB, nullable=False, server_default="{}"),
        sa.Column("config_version", sa.Integer, nullable=False, server_default="0"),
        sa.Column("vars", JSONB, nullable=False, server_default="{}"),
        sa.Column("claim_ts", sa.String, nullable=True),
        sa.Column("last_reconfig_ts", sa.String, nullable=True),
        sa.Column("error_msg", sa.Text, nullable=True),
        sa.Column("host_id", sa.String, sa.ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True),
        sa.Column("ts", sa.String, nullable=False),
    )

    op.create_table(
        "instance_credentials",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("instance_id", sa.String, sa.ForeignKey("managed_instances.id", ondelete="CASCADE"), nullable=False),
        sa.Column("project_id", sa.String, sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.String, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("service_type", sa.String, nullable=False),
        sa.Column("service_name", sa.String, nullable=True),
        sa.Column("username", sa.String, nullable=False),
        sa.Column("password", sa.String, nullable=True),
        sa.Column("token", sa.String, nullable=True),
        sa.Column("connection_url", sa.String, nullable=True),
        sa.Column("connection_port", sa.Integer, nullable=True),
        sa.Column("protocol", sa.String, nullable=True),
        sa.Column("status", sa.String, nullable=False, server_default="active"),
        sa.Column("ts", sa.String, nullable=False),
    )

    op.create_index("ix_instance_credentials_user_project", "instance_credentials", ["user_id", "project_id"])
    op.create_index("ix_managed_instances_status", "managed_instances", ["status"])
    op.create_index("ix_managed_instances_project", "managed_instances", ["project_id"])


def downgrade() -> None:
    op.drop_index("ix_instance_credentials_user_project")
    op.drop_index("ix_managed_instances_status")
    op.drop_index("ix_managed_instances_project")
    op.drop_table("instance_credentials")
    op.drop_table("managed_instances")
    op.drop_table("instance_templates")
