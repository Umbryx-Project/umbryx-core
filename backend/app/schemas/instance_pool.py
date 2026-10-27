from pydantic import BaseModel, field_validator

# Keys inside ManagedInstance.config_current that hold plaintext generated
# secrets (passwords/tokens/PSKs). Kept in one place so ManagedInstanceOut's
# redaction and core.instance_manager._extract_secrets never drift apart.
CONFIG_SECRET_KEYS = {
    "psk",
    "PSK",
    "password",
    "PASSWORD",
    "admin_pass",
    "auth",
    "AUTH",
    "MYTHIC_ADMIN_PASS",
    "COVENANT_PASS",
    "GOPHISH_ADMIN_PASS",
}


def redact_config_secrets(value):
    """Recursively redact CONFIG_SECRET_KEYS anywhere in a nested
    dict/list — config_current is built by config_renderer.render_config(),
    which recurses into dicts and lists (e.g. a template's `env` block), so
    a secret is not guaranteed to sit at the top level. A top-level-only
    redaction leaves any secret nested under a sub-object exposed in
    plaintext (found in post-commit review of security audit finding F6)."""
    if isinstance(value, dict):
        return {
            k: (
                "***"
                if k in CONFIG_SECRET_KEYS and isinstance(v, str)
                else redact_config_secrets(v)
            )
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact_config_secrets(item) for item in value]
    return value


class InstanceTemplateCreate(BaseModel):
    name: str
    service_type: str = "custom"
    description: str | None = None
    manifest: dict = {}
    config_template: dict = {}
    config_schema: dict = {}
    default_replicas: int = 1
    resource_limits: dict = {}
    ports: list[dict] = []
    health_check_path: str | None = None
    min_pool_size: int = 0
    is_builtin: bool = False
    image_registry: str | None = None
    image_delivery: str = "registry"
    ssh_host: str | None = None
    org_id: str | None = None


class InstanceTemplateUpdate(BaseModel):
    name: str | None = None
    service_type: str | None = None
    description: str | None = None
    manifest: dict | None = None
    config_template: dict | None = None
    config_schema: dict | None = None
    default_replicas: int | None = None
    resource_limits: dict | None = None
    ports: list[dict] | None = None
    health_check_path: str | None = None
    min_pool_size: int | None = None
    image_registry: str | None = None
    image_delivery: str | None = None
    ssh_host: str | None = None


class InstanceTemplateOut(BaseModel):
    id: str
    name: str
    service_type: str
    description: str | None
    manifest: dict
    config_template: dict
    config_schema: dict
    default_replicas: int
    resource_limits: dict
    ports: list[dict]
    health_check_path: str | None
    min_pool_size: int
    is_builtin: bool
    image_registry: str | None
    image_delivery: str
    ssh_host: str | None
    org_id: str | None
    created_by: str | None
    ts: str

    model_config = {"from_attributes": True}


class ManagedInstanceOut(BaseModel):
    id: str
    template_id: str | None
    status: str
    project_id: str | None
    namespace: str
    deployment_name: str
    configmap_name: str
    service_name: str | None
    config_current: dict
    config_version: int
    vars: dict
    claim_ts: str | None
    last_reconfig_ts: str | None
    error_msg: str | None
    host_id: str | None
    ts: str

    model_config = {"from_attributes": True}

    @field_validator("config_current", mode="before")
    @classmethod
    def _redact_secrets(cls, v: dict | None) -> dict:
        """Never expose generated secrets (password/PSK/token/...) through this
        endpoint — the same values are readable, permission-gated, via the
        InstanceCredential API (credentials.read_secret)."""
        if not v:
            return {}
        return redact_config_secrets(v)


class ProvisionRequest(BaseModel):
    template_id: str
    count: int = 1


class ClaimRequest(BaseModel):
    project_id: str
    vars: dict = {}


class InstanceCredentialOut(BaseModel):
    id: str
    instance_id: str
    project_id: str
    user_id: str
    service_type: str
    service_name: str | None
    username: str
    password: str | None
    token: str | None
    connection_url: str | None
    connection_port: int | None
    protocol: str | None
    status: str
    ts: str

    model_config = {"from_attributes": True}

    @classmethod
    def from_orm_with_decrypt(cls, obj) -> "InstanceCredentialOut":
        from ..core.crypto import decrypt_str

        data = {
            "id": obj.id,
            "instance_id": obj.instance_id,
            "project_id": obj.project_id,
            "user_id": obj.user_id,
            "service_type": obj.service_type,
            "service_name": obj.service_name,
            "username": obj.username,
            "password": decrypt_str(obj.password) if obj.password else None,
            "token": decrypt_str(obj.token) if obj.token else None,
            "connection_url": obj.connection_url,
            "connection_port": obj.connection_port,
            "protocol": obj.protocol,
            "status": obj.status,
            "ts": obj.ts,
        }
        return cls(**data)


class InstanceStatusOut(BaseModel):
    id: str
    status: str
    namespace: str
    deployment: str
    config_version: int
    k8s: dict
    service_url: str | None

    model_config = {"from_attributes": True}
