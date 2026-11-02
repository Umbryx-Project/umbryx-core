"""infra_v2: providers, nodes, templates, blueprints, stacks, services, links, credentials, agents, fileshares, operator_access

Revision ID: 054
Revises: 053
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "054"
down_revision = "053"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "infra_providers",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("org_id", sa.String, sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True),
        sa.Column("name", sa.String, nullable=False),
        sa.Column("type", sa.String, nullable=False, server_default="manual"),
        sa.Column("credentials", JSONB, nullable=False, server_default="{}"),
        sa.Column("config", JSONB, nullable=False, server_default="{}"),
        sa.Column("status", sa.String, nullable=False, server_default="active"),
        sa.Column("created_at", sa.String, nullable=False),
        sa.Column("created_by", sa.String, nullable=True),
    )

    op.create_table(
        "infra_nodes",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("provider_id", sa.String, sa.ForeignKey("infra_providers.id", ondelete="SET NULL"), nullable=True),
        sa.Column("project_id", sa.String, sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=True),
        sa.Column("name", sa.String, nullable=False),
        sa.Column("provider", sa.String, nullable=False, server_default="manual"),
        sa.Column("host", sa.String, nullable=False),
        sa.Column("port", sa.Integer, nullable=False, server_default="22"),
        sa.Column("ssh_user", sa.String, nullable=False, server_default="root"),
        sa.Column("ssh_key", sa.Text, nullable=True),
        sa.Column("kubeconfig", sa.Text, nullable=True),
        sa.Column("ip_addresses", JSONB, nullable=False, server_default="[]"),
        sa.Column("labels", JSONB, nullable=False, server_default="{}"),
        sa.Column("resources", JSONB, nullable=False, server_default="{}"),
        sa.Column("status", sa.String, nullable=False, server_default="available"),
        sa.Column("last_check", sa.String, nullable=True),
        sa.Column("error", sa.String, nullable=True),
        sa.Column("created_at", sa.String, nullable=False),
        sa.Column("created_by", sa.String, nullable=True),
    )
    op.create_index("ix_infra_nodes_provider", "infra_nodes", ["provider_id"])
    op.create_index("ix_infra_nodes_project", "infra_nodes", ["project_id"])
    op.create_index("ix_infra_nodes_status", "infra_nodes", ["status"])

    op.create_table(
        "infra_service_templates",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("name", sa.String, nullable=False),
        sa.Column("type", sa.String, nullable=False, server_default="c2"),
        sa.Column("version", sa.String, nullable=False, server_default="latest"),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("image_source", sa.String, nullable=False, server_default="registry"),
        sa.Column("image_ref", sa.String, nullable=False, server_default=""),
        sa.Column("config_schema", JSONB, nullable=False, server_default="{}"),
        sa.Column("default_config", JSONB, nullable=False, server_default="{}"),
        sa.Column("args_template", JSONB, nullable=False, server_default="[]"),
        sa.Column("ports_template", JSONB, nullable=False, server_default="[]"),
        sa.Column("can_generate_agents", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("agent_types", JSONB, nullable=False, server_default="[]"),
        sa.Column("is_builtin", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("meta", JSONB, nullable=False, server_default="{}"),
        sa.Column("created_at", sa.String, nullable=False),
    )
    op.create_index("ix_svc_templates_type", "infra_service_templates", ["type"])

    op.create_table(
        "infra_stack_blueprints",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("name", sa.String, nullable=False),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("services", JSONB, nullable=False, server_default="[]"),
        sa.Column("links", JSONB, nullable=False, server_default="[]"),
        sa.Column("is_builtin", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("org_id", sa.String, sa.ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True),
        sa.Column("created_at", sa.String, nullable=False),
        sa.Column("created_by", sa.String, nullable=True),
    )

    op.create_table(
        "infra_stacks",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("project_id", sa.String, sa.ForeignKey("projects.id", ondelete="SET NULL"), nullable=True),
        sa.Column("blueprint_id", sa.String, sa.ForeignKey("infra_stack_blueprints.id", ondelete="SET NULL"), nullable=True),
        sa.Column("name", sa.String, nullable=False),
        sa.Column("status", sa.String, nullable=False, server_default="designing"),
        sa.Column("mode", sa.String, nullable=False, server_default="standby"),
        sa.Column("deployment_log", JSONB, nullable=False, server_default="[]"),
        sa.Column("bound_at", sa.String, nullable=True),
        sa.Column("bound_by", sa.String, nullable=True),
        sa.Column("created_at", sa.String, nullable=False),
        sa.Column("created_by", sa.String, nullable=True),
        sa.Column("error", sa.String, nullable=True),
    )
    op.create_index("ix_infra_stacks_project", "infra_stacks", ["project_id"])
    op.create_index("ix_infra_stacks_status", "infra_stacks", ["status"])
    op.create_index("ix_infra_stacks_mode", "infra_stacks", ["mode"])

    op.create_table(
        "infra_stack_services",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("stack_id", sa.String, sa.ForeignKey("infra_stacks.id", ondelete="CASCADE"), nullable=False),
        sa.Column("node_id", sa.String, sa.ForeignKey("infra_nodes.id", ondelete="SET NULL"), nullable=True),
        sa.Column("template_id", sa.String, sa.ForeignKey("infra_service_templates.id", ondelete="SET NULL"), nullable=True),
        sa.Column("role", sa.String, nullable=False, server_default="c2"),
        sa.Column("name", sa.String, nullable=False, server_default=""),
        sa.Column("container_id", sa.String, nullable=True),
        sa.Column("status", sa.String, nullable=False, server_default="pending"),
        sa.Column("health_url", sa.String, nullable=True),
        sa.Column("resolved_config", JSONB, nullable=False, server_default="{}"),
        sa.Column("ports", JSONB, nullable=False, server_default="[]"),
        sa.Column("connection_url", sa.String, nullable=True),
        sa.Column("admin_url", sa.String, nullable=True),
        sa.Column("error", sa.String, nullable=True),
        sa.Column("started_at", sa.String, nullable=True),
    )
    op.create_index("ix_stack_services_stack", "infra_stack_services", ["stack_id"])
    op.create_index("ix_stack_services_status", "infra_stack_services", ["status"])

    op.create_table(
        "infra_service_links",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("stack_id", sa.String, sa.ForeignKey("infra_stacks.id", ondelete="CASCADE"), nullable=False),
        sa.Column("from_service_id", sa.String, sa.ForeignKey("infra_stack_services.id", ondelete="CASCADE"), nullable=False),
        sa.Column("to_service_id", sa.String, sa.ForeignKey("infra_stack_services.id", ondelete="CASCADE"), nullable=False),
        sa.Column("link_type", sa.String, nullable=False, server_default="http_proxy"),
        sa.Column("config", JSONB, nullable=False, server_default="{}"),
        sa.Column("status", sa.String, nullable=False, server_default="pending"),
        sa.Column("verified_at", sa.String, nullable=True),
        sa.Column("error", sa.String, nullable=True),
    )
    op.create_index("ix_service_links_stack", "infra_service_links", ["stack_id"])

    op.create_table(
        "infra_service_credentials",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("stack_id", sa.String, sa.ForeignKey("infra_stacks.id", ondelete="CASCADE"), nullable=False),
        sa.Column("service_id", sa.String, sa.ForeignKey("infra_stack_services.id", ondelete="CASCADE"), nullable=True),
        sa.Column("project_id", sa.String, sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=True),
        sa.Column("purpose", sa.String, nullable=False, server_default="admin_access"),
        sa.Column("label", sa.String, nullable=False, server_default=""),
        sa.Column("username", sa.String, nullable=False, server_default=""),
        sa.Column("secret", sa.Text, nullable=False, server_default=""),
        sa.Column("url", sa.String, nullable=True),
        sa.Column("visible_to_roles", JSONB, nullable=False, server_default="[]"),
        sa.Column("created_at", sa.String, nullable=False),
    )
    op.create_index("ix_svc_creds_stack", "infra_service_credentials", ["stack_id"])
    op.create_index("ix_svc_creds_project", "infra_service_credentials", ["project_id"])

    op.create_table(
        "infra_agent_builds",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("stack_id", sa.String, sa.ForeignKey("infra_stacks.id", ondelete="CASCADE"), nullable=False),
        sa.Column("service_id", sa.String, sa.ForeignKey("infra_stack_services.id", ondelete="CASCADE"), nullable=True),
        sa.Column("agent_type", sa.String, nullable=False, server_default="beacon"),
        sa.Column("filename", sa.String, nullable=False, server_default=""),
        sa.Column("platform", sa.String, nullable=False, server_default="windows"),
        sa.Column("arch", sa.String, nullable=False, server_default="x64"),
        sa.Column("c2_address", sa.String, nullable=True),
        sa.Column("config_hash", sa.String, nullable=True),
        sa.Column("file_path", sa.String, nullable=True),
        sa.Column("download_url", sa.String, nullable=True),
        sa.Column("file_size", sa.Integer, nullable=False, server_default="0"),
        sa.Column("sha256", sa.String, nullable=True),
        sa.Column("created_at", sa.String, nullable=False),
    )
    op.create_index("ix_agent_builds_stack", "infra_agent_builds", ["stack_id"])

    op.create_table(
        "infra_file_shares",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("stack_id", sa.String, sa.ForeignKey("infra_stacks.id", ondelete="CASCADE"), nullable=False),
        sa.Column("service_id", sa.String, sa.ForeignKey("infra_stack_services.id", ondelete="SET NULL"), nullable=True),
        sa.Column("project_id", sa.String, sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=True),
        sa.Column("name", sa.String, nullable=False, server_default="File Share"),
        sa.Column("base_url", sa.String, nullable=False, server_default=""),
        sa.Column("auth_method", sa.String, nullable=False, server_default="basic"),
        sa.Column("credentials", JSONB, nullable=False, server_default="{}"),
        sa.Column("status", sa.String, nullable=False, server_default="pending"),
        sa.Column("created_at", sa.String, nullable=False),
    )

    op.create_table(
        "infra_operator_access",
        sa.Column("id", sa.String, primary_key=True),
        sa.Column("stack_id", sa.String, sa.ForeignKey("infra_stacks.id", ondelete="CASCADE"), nullable=False),
        sa.Column("project_id", sa.String, sa.ForeignKey("projects.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.String, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("c2_username", sa.String, nullable=False, server_default=""),
        sa.Column("c2_password", sa.Text, nullable=False, server_default=""),
        sa.Column("c2_url", sa.String, nullable=True),
        sa.Column("workstation_id", sa.String, nullable=True),
        sa.Column("granted_at", sa.String, nullable=False),
        sa.Column("granted_by", sa.String, nullable=True),
    )
    op.create_index("ix_operator_access_stack", "infra_operator_access", ["stack_id"])
    op.create_index("ix_operator_access_user", "infra_operator_access", ["user_id"])


def downgrade() -> None:
    op.drop_table("infra_operator_access")
    op.drop_table("infra_file_shares")
    op.drop_table("infra_agent_builds")
    op.drop_table("infra_service_credentials")
    op.drop_table("infra_service_links")
    op.drop_table("infra_stack_services")
    op.drop_table("infra_stacks")
    op.drop_table("infra_stack_blueprints")
    op.drop_table("infra_service_templates")
    op.drop_table("infra_nodes")
    op.drop_table("infra_providers")
