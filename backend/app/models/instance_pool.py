from sqlalchemy import Boolean, Column, ForeignKey, Integer, String, Text

from ..database import Base
from ._types import JSONB


class InstanceTemplate(Base):
    __tablename__ = "instance_templates"

    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    service_type = Column(String, nullable=False, default="custom")
    description = Column(Text, nullable=True)
    manifest = Column(JSONB, nullable=False, default=dict)
    config_template = Column(JSONB, nullable=False, default=dict)
    config_schema = Column(JSONB, nullable=False, default=dict)
    default_replicas = Column(Integer, nullable=False, default=1)
    resource_limits = Column(JSONB, nullable=False, default=dict)
    ports = Column(JSONB, nullable=False, default=list)
    health_check_path = Column(String, nullable=True)
    min_pool_size = Column(Integer, nullable=False, default=0)
    is_builtin = Column(Boolean, nullable=False, default=False, server_default="false")
    image_registry = Column(String, nullable=True)
    image_delivery = Column(String, nullable=False, default="registry", server_default="registry")
    ssh_host = Column(String, nullable=True)
    org_id = Column(String, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True)
    created_by = Column(String, nullable=True)
    ts = Column(String, nullable=False)


class ManagedInstance(Base):
    __tablename__ = "managed_instances"

    id = Column(String, primary_key=True)
    template_id = Column(
        String, ForeignKey("instance_templates.id", ondelete="SET NULL"), nullable=True
    )
    status = Column(String, nullable=False, default="provisioning")
    project_id = Column(String, ForeignKey("projects.id", ondelete="SET NULL"), nullable=True)
    namespace = Column(String, nullable=False)
    deployment_name = Column(String, nullable=False)
    configmap_name = Column(String, nullable=False)
    service_name = Column(String, nullable=True)
    config_current = Column(JSONB, nullable=False, default=dict)
    config_version = Column(Integer, nullable=False, default=0)
    vars = Column(JSONB, nullable=False, default=dict)
    claim_ts = Column(String, nullable=True)
    last_reconfig_ts = Column(String, nullable=True)
    error_msg = Column(Text, nullable=True)
    host_id = Column(String, ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True)
    ts = Column(String, nullable=False)


class InstanceCredential(Base):
    __tablename__ = "instance_credentials"

    id = Column(String, primary_key=True)
    instance_id = Column(
        String, ForeignKey("managed_instances.id", ondelete="CASCADE"), nullable=False
    )
    project_id = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    service_type = Column(String, nullable=False)
    service_name = Column(String, nullable=True)
    username = Column(String, nullable=False)
    password = Column(String, nullable=True)
    token = Column(String, nullable=True)
    connection_url = Column(String, nullable=True)
    connection_port = Column(Integer, nullable=True)
    protocol = Column(String, nullable=True)
    status = Column(String, nullable=False, default="active", server_default="active")
    ts = Column(String, nullable=False)
