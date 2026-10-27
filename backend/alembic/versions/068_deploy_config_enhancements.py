"""Deploy config enhancements: config_files, default_env, public_host, project env

Revision ID: 068
Revises: 067
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "068"
down_revision = "067"
branch_labels = None
depends_on = None


def upgrade():
    # ServiceTemplate: separate default_env from default_config
    op.add_column("infra_service_templates",
                  sa.Column("default_env", JSONB, nullable=False, server_default="{}"))

    # StackService: config_files for ConfigMap/bind-mount support
    op.add_column("infra_stack_services",
                  sa.Column("config_files", JSONB, nullable=False, server_default="[]"))

    # InfraProvider: explicit public_host override (for NAT/cloud scenarios)
    op.add_column("infra_providers",
                  sa.Column("public_host", sa.String, nullable=True))

    # Project: env_vars for project-level environment variables
    op.add_column("projects",
                  sa.Column("env_vars", JSONB, nullable=False, server_default="{}"))

    # InfraStack: env_vars for stack-level env overrides
    op.add_column("infra_stacks",
                  sa.Column("env_vars", JSONB, nullable=False, server_default="{}"))


def downgrade():
    op.drop_column("infra_stacks", "env_vars")
    op.drop_column("projects", "env_vars")
    op.drop_column("infra_providers", "public_host")
    op.drop_column("infra_stack_services", "config_files")
    op.drop_column("infra_service_templates", "default_env")
