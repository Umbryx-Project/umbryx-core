from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Text

from ..database import Base
from ._types import JSONB


class InfraProvider(Base):
    __tablename__ = "infra_providers"

    id = Column(String, primary_key=True)
    org_id = Column(String, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True)
    name = Column(String, nullable=False)
    type = Column(String, nullable=False, default="manual")
    category = Column(String, nullable=False, default="cloud")
    credentials = Column(JSONB, nullable=False, default=dict)
    connection = Column(JSONB, nullable=False, default=dict)
    config = Column(JSONB, nullable=False, default=dict)
    host = Column(String, nullable=True)
    public_host = Column(String, nullable=True)
    port = Column(Integer, nullable=False, default=22)
    ssh_user = Column(String, nullable=False, default="root")
    ssh_key = Column(Text, nullable=True)
    kubeconfig = Column(Text, nullable=True)
    deploy_mode = Column(String, nullable=False, default="ssh")
    status = Column(String, nullable=False, default="active")
    last_check_ok = Column(Boolean, nullable=True)
    last_check_msg = Column(String, nullable=True)
    last_check = Column(String, nullable=True)
    created_at = Column(String, nullable=False)
    created_by = Column(String, nullable=True)


class InfraNode(Base):
    __tablename__ = "infra_nodes"

    id = Column(String, primary_key=True)
    provider_id = Column(
        String, ForeignKey("infra_providers.id", ondelete="SET NULL"), nullable=True
    )
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=True)
    name = Column(String, nullable=False)
    provider = Column(String, nullable=False, default="manual")
    host = Column(String, nullable=False)
    port = Column(Integer, nullable=False, default=22)
    ssh_user = Column(String, nullable=False, default="root")
    ssh_key = Column(Text, nullable=True)
    kubeconfig = Column(Text, nullable=True)
    ip_addresses = Column(JSONB, nullable=False, default=list)
    labels = Column(JSONB, nullable=False, default=dict)
    resources = Column(JSONB, nullable=False, default=dict)
    status = Column(String, nullable=False, default="available")
    last_check = Column(String, nullable=True)
    error = Column(String, nullable=True)
    created_at = Column(String, nullable=False)
    created_by = Column(String, nullable=True)


class ServiceTemplate(Base):
    __tablename__ = "infra_service_templates"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    type = Column(String, nullable=False, default="c2")
    version = Column(String, nullable=False, default="latest")
    description = Column(Text, nullable=False, default="")
    image_source = Column(String, nullable=False, default="registry")
    image_ref = Column(String, nullable=False, default="")
    config_schema = Column(JSONB, nullable=False, default=dict)
    default_config = Column(JSONB, nullable=False, default=dict)
    default_env = Column(JSONB, nullable=False, default=dict)
    args_template = Column(JSONB, nullable=False, default=list)
    ports_template = Column(JSONB, nullable=False, default=list)
    default_config_files = Column(JSONB, nullable=False, default=list)
    can_generate_agents = Column(Boolean, nullable=False, default=False, server_default="false")
    agent_types = Column(JSONB, nullable=False, default=list)
    is_builtin = Column(Boolean, nullable=False, default=False, server_default="false")
    meta = Column(JSONB, nullable=False, default=dict)
    created_at = Column(String, nullable=False)


class StackBlueprint(Base):
    __tablename__ = "infra_stack_blueprints"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=False, default="")
    services = Column(JSONB, nullable=False, default=list)
    links = Column(JSONB, nullable=False, default=list)
    is_builtin = Column(Boolean, nullable=False, default=False, server_default="false")
    org_id = Column(String, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True)
    created_at = Column(String, nullable=False)
    created_by = Column(String, nullable=True)


class InfraStack(Base):
    __tablename__ = "infra_stacks"

    id = Column(String, primary_key=True)
    project_id = Column(String, ForeignKey("projects.id", ondelete="SET NULL"), nullable=True)
    blueprint_id = Column(
        String, ForeignKey("infra_stack_blueprints.id", ondelete="SET NULL"), nullable=True
    )
    name = Column(String, nullable=False)
    status = Column(String, nullable=False, default="designing")
    mode = Column(String, nullable=False, default="standalone")
    deployment_log = Column(JSONB, nullable=False, default=list)
    bound_at = Column(String, nullable=True)
    bound_by = Column(String, nullable=True)
    detached_at = Column(String, nullable=True)
    detached_from_project = Column(String, nullable=True)
    created_at = Column(String, nullable=False)
    created_by = Column(String, nullable=True)
    error = Column(String, nullable=True)
    env_vars = Column(JSONB, nullable=False, default=dict)


class StackService(Base):
    __tablename__ = "infra_stack_services"

    id = Column(String, primary_key=True)
    stack_id = Column(String, ForeignKey("infra_stacks.id", ondelete="CASCADE"), nullable=False)
    provider_id = Column(
        String, ForeignKey("infra_providers.id", ondelete="SET NULL"), nullable=True
    )
    template_id = Column(
        String, ForeignKey("infra_service_templates.id", ondelete="SET NULL"), nullable=True
    )
    role = Column(String, nullable=False, default="c2")
    name = Column(String, nullable=False, default="")
    # Per-service project override (multi-engagement clusters: 7 C2
    # instances — each in its own project; shared edge services stay
    # stack-level). Falls back to stack.project_id everywhere.
    project_id = Column(
        String, ForeignKey("projects.id", ondelete="SET NULL"), nullable=True, index=True
    )
    container_id = Column(String, nullable=True)
    deploy_mode = Column(String, nullable=False, default="ssh")
    status = Column(String, nullable=False, default="pending")
    health_url = Column(String, nullable=True)
    resolved_config = Column(JSONB, nullable=False, default=dict)
    ports = Column(JSONB, nullable=False, default=list)
    connection_url = Column(String, nullable=True)
    admin_url = Column(String, nullable=True)
    error = Column(String, nullable=True)
    started_at = Column(String, nullable=True)
    config_hash = Column(String, nullable=True)
    integration_steps = Column(JSONB, nullable=False, default=dict)
    config_files = Column(JSONB, nullable=False, default=list)
    integration_delivery = Column(JSONB, nullable=False, default=dict)
    integration_status = Column(String, nullable=False, default="pending")
    integration_payload = Column(JSONB, nullable=False, default=dict)


class ServiceToken(Base):
    __tablename__ = "infra_service_tokens"

    id = Column(String, primary_key=True)
    token_hash = Column(String, nullable=False, unique=True, index=True)
    service_id = Column(
        String, ForeignKey("infra_stack_services.id", ondelete="CASCADE"), nullable=False
    )
    stack_id = Column(String, ForeignKey("infra_stacks.id", ondelete="CASCADE"), nullable=False)
    project_id = Column(String, nullable=True)
    role = Column(String, nullable=False, default="")
    scopes = Column(JSONB, nullable=False, default=list)
    created_at = Column(String, nullable=False)
    last_used = Column(String, nullable=True)
    confirmed_at = Column(String, nullable=True)


class ServiceLink(Base):
    __tablename__ = "infra_service_links"

    id = Column(String, primary_key=True)
    stack_id = Column(String, ForeignKey("infra_stacks.id", ondelete="CASCADE"), nullable=False)
    from_service_id = Column(
        String, ForeignKey("infra_stack_services.id", ondelete="CASCADE"), nullable=False
    )
    to_service_id = Column(
        String, ForeignKey("infra_stack_services.id", ondelete="CASCADE"), nullable=False
    )
    link_type = Column(String, nullable=False, default="http_proxy")
    config = Column(JSONB, nullable=False, default=dict)
    status = Column(String, nullable=False, default="pending")
    verified_at = Column(String, nullable=True)
    error = Column(String, nullable=True)


class ServiceCredential(Base):
    __tablename__ = "infra_service_credentials"

    id = Column(String, primary_key=True)
    stack_id = Column(String, ForeignKey("infra_stacks.id", ondelete="CASCADE"), nullable=False)
    service_id = Column(
        String, ForeignKey("infra_stack_services.id", ondelete="CASCADE"), nullable=True
    )
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=True)
    purpose = Column(String, nullable=False, default="admin_access")
    label = Column(String, nullable=False, default="")
    username = Column(String, nullable=False, default="")
    secret = Column(Text, nullable=False, default="")
    url = Column(String, nullable=True)
    visible_to_roles = Column(JSONB, nullable=False, default=list)
    created_at = Column(String, nullable=False)


class AgentBuild(Base):
    __tablename__ = "infra_agent_builds"

    id = Column(String, primary_key=True)
    stack_id = Column(String, ForeignKey("infra_stacks.id", ondelete="CASCADE"), nullable=False)
    service_id = Column(
        String, ForeignKey("infra_stack_services.id", ondelete="CASCADE"), nullable=True
    )
    agent_type = Column(String, nullable=False, default="beacon")
    filename = Column(String, nullable=False, default="")
    platform = Column(String, nullable=False, default="windows")
    arch = Column(String, nullable=False, default="x64")
    c2_address = Column(String, nullable=True)
    config_hash = Column(String, nullable=True)
    file_path = Column(String, nullable=True)
    download_url = Column(String, nullable=True)
    file_size = Column(Integer, nullable=False, default=0)
    sha256 = Column(String, nullable=True)
    created_at = Column(String, nullable=False)


class FileShare(Base):
    __tablename__ = "infra_file_shares"

    id = Column(String, primary_key=True)
    stack_id = Column(String, ForeignKey("infra_stacks.id", ondelete="CASCADE"), nullable=False)
    service_id = Column(
        String, ForeignKey("infra_stack_services.id", ondelete="SET NULL"), nullable=True
    )
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=True)
    name = Column(String, nullable=False, default="File Share")
    base_url = Column(String, nullable=False, default="")
    auth_method = Column(String, nullable=False, default="basic")
    credentials = Column(JSONB, nullable=False, default=dict)
    status = Column(String, nullable=False, default="pending")
    created_at = Column(String, nullable=False)


class OperatorAccess(Base):
    __tablename__ = "infra_operator_access"

    id = Column(String, primary_key=True)
    stack_id = Column(String, ForeignKey("infra_stacks.id", ondelete="CASCADE"), nullable=False)
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    c2_username = Column(String, nullable=False, default="")
    c2_password = Column(Text, nullable=False, default="")
    c2_url = Column(String, nullable=True)
    workstation_id = Column(String, nullable=True)
    granted_at = Column(String, nullable=False)
    granted_by = Column(String, nullable=True)


class DeployStep(Base):
    """Tracks each step of a deployment pipeline with status, logs, and timing."""

    __tablename__ = "infra_deploy_steps"

    id = Column(String, primary_key=True)
    stack_id = Column(String, ForeignKey("infra_stacks.id", ondelete="CASCADE"), nullable=False)
    service_id = Column(
        String, ForeignKey("infra_stack_services.id", ondelete="CASCADE"), nullable=True
    )
    step_type = Column(String, nullable=False)
    step_name = Column(String, nullable=False, default="")
    status = Column(String, nullable=False, default="pending")
    message = Column(Text, nullable=False, default="")
    details = Column(JSONB, nullable=False, default=dict)
    started_at = Column(String, nullable=True)
    completed_at = Column(String, nullable=True)
    duration_ms = Column(Integer, nullable=True)
    created_at = Column(String, nullable=False)


class DevOpsLogEntry(Base):
    """Centralized DevOps activity log — aggregates all infra operations across stacks."""

    __tablename__ = "infra_devops_log"

    id = Column(String, primary_key=True)
    stack_id = Column(String, ForeignKey("infra_stacks.id", ondelete="CASCADE"), nullable=True)
    service_id = Column(String, nullable=True)
    provider_id = Column(String, nullable=True)
    level = Column(String, nullable=False, default="info")
    category = Column(String, nullable=False, default="infra")
    message = Column(Text, nullable=False)
    details = Column(JSONB, nullable=False, default=dict)
    actor = Column(String, nullable=True)
    created_at = Column(String, nullable=False)
