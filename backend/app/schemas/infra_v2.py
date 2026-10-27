import re

from pydantic import BaseModel, field_validator

# ═══════ Providers ═══════


class ProviderCreate(BaseModel):
    name: str
    type: str = "manual"
    category: str = "cloud"
    connection: dict = {}
    credentials: dict = {}
    config: dict = {}
    host: str | None = None
    port: int = 22
    ssh_user: str = "root"
    ssh_key: str | None = None
    kubeconfig: str | None = None
    deploy_mode: str = "ssh"
    org_id: str | None = None


class ProviderTestRequest(BaseModel):
    type: str
    connection: dict = {}
    host: str | None = None
    port: int = 22
    ssh_user: str = "root"
    ssh_key: str | None = None
    kubeconfig: str | None = None


class ProviderUpdate(BaseModel):
    name: str | None = None
    type: str | None = None
    category: str | None = None
    connection: dict | None = None
    credentials: dict | None = None
    config: dict | None = None
    host: str | None = None
    port: int | None = None
    ssh_user: str | None = None
    ssh_key: str | None = None
    kubeconfig: str | None = None
    deploy_mode: str | None = None
    public_host: str | None = None
    status: str | None = None


class ProviderOut(BaseModel):
    id: str
    org_id: str | None
    name: str
    type: str
    category: str
    credentials: dict
    connection: dict
    config: dict
    host: str | None = None
    port: int = 22
    ssh_user: str = "root"
    ssh_key: str | None = None
    kubeconfig: str | None = None
    deploy_mode: str = "ssh"
    public_host: str | None = None
    status: str
    last_check_ok: bool | None = None
    last_check_msg: str | None = None
    last_check: str | None = None
    created_at: str
    created_by: str | None

    class Config:
        from_attributes = True


# ═══════ Nodes ═══════


class NodeCreate(BaseModel):
    name: str
    provider_id: str | None = None
    project_id: str | None = None
    provider: str = "manual"
    host: str
    port: int = 22
    ssh_user: str = "root"
    ssh_key: str | None = None
    kubeconfig: str | None = None
    ip_addresses: list = []
    labels: dict = {}


class NodeUpdate(BaseModel):
    name: str | None = None
    host: str | None = None
    port: int | None = None
    ssh_user: str | None = None
    ssh_key: str | None = None
    kubeconfig: str | None = None
    ip_addresses: list | None = None
    labels: dict | None = None
    status: str | None = None


class NodeOut(BaseModel):
    id: str
    provider_id: str | None
    project_id: str | None
    name: str
    provider: str
    host: str
    port: int
    ssh_user: str
    ip_addresses: list
    labels: dict
    resources: dict
    status: str
    last_check: str | None
    error: str | None
    created_at: str
    created_by: str | None

    class Config:
        from_attributes = True


# ═══════ Service Templates ═══════


class ServiceTemplateCreate(BaseModel):
    name: str
    type: str = "c2"
    version: str = "latest"
    description: str = ""
    image_source: str = "registry"
    image_ref: str = ""
    config_schema: dict = {}
    default_config: dict = {}
    default_env: dict = {}
    args_template: list = []
    ports_template: list = []
    default_config_files: list = []
    can_generate_agents: bool = False
    agent_types: list = []
    meta: dict = {}


class ServiceTemplateUpdate(BaseModel):
    name: str | None = None
    type: str | None = None
    version: str | None = None
    description: str | None = None
    image_source: str | None = None
    image_ref: str | None = None
    config_schema: dict | None = None
    default_config: dict | None = None
    default_env: dict | None = None
    args_template: list | None = None
    ports_template: list | None = None
    default_config_files: list | None = None
    can_generate_agents: bool | None = None
    agent_types: list | None = None
    meta: dict | None = None


class ServiceTemplateOut(BaseModel):
    id: str
    name: str
    type: str
    version: str
    description: str
    image_source: str
    image_ref: str
    config_schema: dict
    default_config: dict
    default_env: dict
    args_template: list
    ports_template: list
    default_config_files: list = []
    can_generate_agents: bool
    agent_types: list
    is_builtin: bool
    meta: dict
    created_at: str

    class Config:
        from_attributes = True


# ═══════ Stack Blueprints ═══════


class BlueprintCreate(BaseModel):
    name: str
    description: str = ""
    services: list = []
    links: list = []
    org_id: str | None = None


class BlueprintUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    services: list | None = None
    links: list | None = None


class BlueprintOut(BaseModel):
    id: str
    name: str
    description: str
    services: list
    links: list
    is_builtin: bool
    org_id: str | None
    created_at: str
    created_by: str | None

    class Config:
        from_attributes = True


# ═══════ Stacks ═══════


class StackDeployRequest(BaseModel):
    blueprint_id: str | None = None
    project_id: str | None = None
    bind_to_project: bool = False
    name: str
    mode: str = "standalone"
    env_vars: dict = {}
    services: list = []
    links: list = []


class StackBindRequest(BaseModel):
    project_id: str


class StackOut(BaseModel):
    id: str
    project_id: str | None
    blueprint_id: str | None
    name: str
    status: str
    mode: str
    deployment_log: list
    env_vars: dict = {}
    bound_at: str | None
    bound_by: str | None
    detached_at: str | None = None
    detached_from_project: str | None = None
    created_at: str
    created_by: str | None
    error: str | None

    class Config:
        from_attributes = True


# ═══════ Stack Services ═══════


# Security audit 2026-10-07 (finding 5): provision-time admin passwords live
# inside StackService.resolved_config (top-level admin_password/secret_path
# and env.UMBRYX_ADMIN_PASSWORD / env.ADMIN_PASSWORD). The API must not hand
# them back in plaintext — redact on serialization. The apply path restores
# the stored value when it sees the marker round-tripped (see
# ee/routers/infra_v2_api.py::_restore_redacted_secrets).
RESOLVED_CONFIG_REDACTED = "__umbryx_redacted__"
_RESOLVED_CONFIG_SECRET_KEYS = {"admin_password", "umbryx_admin_password", "password", "secret", "secret_path"}

# Security audit 2026-10-09 (track C): provision-time credentials also live in
# StackService.config_files content (creds.py parses the REAL password out of
# them). Same contract — never hand secrets back via the API. Line-based
# masking of yaml/env/json-ish key-value lines; deploy methods read the raw
# DB column, so rendering is unaffected.
_CONFIG_FILE_LINE_RE = re.compile(
    r'^(?P<prefix>\s*(?:"(?P<qkey>[^"]+)"|(?P<bkey>[A-Za-z0-9_.\-]+))\s*[:=]\s*)(?P<rest>.*)$'
)
_CONFIG_FILE_SECRET_KEY_RE = re.compile(
    r"password|passwd|secret|token|api_?key|private_?key|passphrase", re.IGNORECASE
)


def redact_config_file_content(content) -> str:
    if not isinstance(content, str) or not content:
        return content

    def _mask_json_pair(m):
        key = m.group("jkey")
        if _CONFIG_FILE_SECRET_KEY_RE.search(key):
            return f'"{key}": "{RESOLVED_CONFIG_REDACTED}"'
        return m.group(0)

    def _mask_line(line: str) -> str:
        m = _CONFIG_FILE_LINE_RE.match(line)
        if not m:
            return line
        key = m.group("qkey") or m.group("bkey") or ""
        rest = m.group("rest")
        if not key or not rest.strip() or not _CONFIG_FILE_SECRET_KEY_RE.search(key):
            return line
        masked = f'"{RESOLVED_CONFIG_REDACTED}"' if rest.lstrip().startswith('"') else RESOLVED_CONFIG_REDACTED
        return m.group("prefix") + masked

    # pass 1: inline JSON pairs (compact one-line {"k": "v", ...})
    text = re.sub(r'"(?P<jkey>[^"\n]+)"\s*:\s*"[^"\n]*"', _mask_json_pair, content)
    # pass 2: line-based yaml/env masking
    return "\n".join(_mask_line(ln) for ln in text.splitlines())


def redact_config_files(files) -> list:
    if not isinstance(files, list):
        return files
    redacted = []
    for cf in files:
        if isinstance(cf, dict):
            cf = dict(cf)
            if "content" in cf:
                cf["content"] = redact_config_file_content(cf.get("content"))
        redacted.append(cf)
    return redacted


def redact_credential_values(creds) -> dict:
    """Mask every value of a credentials mapping — used for file-share style
    stores where any value may be a password/token; keys stay visible."""
    if not isinstance(creds, dict):
        return creds
    return {k: RESOLVED_CONFIG_REDACTED for k in creds}


def redact_resolved_config(config: dict) -> dict:
    if not isinstance(config, dict):
        return config
    out = {}
    for k, v in config.items():
        if k == "env" and isinstance(v, dict):
            out[k] = redact_resolved_config(v)
        elif k.lower() in _RESOLVED_CONFIG_SECRET_KEYS and isinstance(v, str) and v:
            out[k] = RESOLVED_CONFIG_REDACTED
        else:
            out[k] = v
    return out


class StackServiceOut(BaseModel):
    id: str
    stack_id: str
    provider_id: str | None
    template_id: str | None
    role: str
    name: str
    container_id: str | None
    deploy_mode: str = "ssh"
    status: str
    health_url: str | None
    resolved_config: dict
    ports: list
    connection_url: str | None
    admin_url: str | None
    error: str | None
    started_at: str | None
    config_files: list = []
    integration_steps: dict = {}
    integration_status: str = "pending"

    @field_validator("resolved_config", mode="before")
    @classmethod
    def _scrub_resolved_config(cls, value):
        return redact_resolved_config(value)

    @field_validator("config_files", mode="before")
    @classmethod
    def _scrub_config_files(cls, value):
        return redact_config_files(value)

    class Config:
        from_attributes = True


class ServiceReconfigRequest(BaseModel):
    config: dict


class ApplyServiceItem(BaseModel):
    id: str | None = None
    name: str = ""
    role: str = "c2"
    config: dict = {}
    ports: list = []


class ApplyChangesRequest(BaseModel):
    services: list[ApplyServiceItem] = []


# ═══════ Service Links ═══════


class ServiceLinkOut(BaseModel):
    id: str
    stack_id: str
    from_service_id: str
    to_service_id: str
    link_type: str
    config: dict
    status: str
    verified_at: str | None
    error: str | None

    class Config:
        from_attributes = True


# ═══════ Credentials ═══════


class CredentialCreate(BaseModel):
    service_id: str | None = None
    purpose: str = "admin_access"
    label: str = ""
    username: str = ""
    secret: str = ""
    url: str | None = None
    visible_to_roles: list = []


class CredentialOut(BaseModel):
    id: str
    stack_id: str
    service_id: str | None
    project_id: str | None
    purpose: str
    label: str
    username: str
    secret: str
    url: str | None
    visible_to_roles: list
    created_at: str

    class Config:
        from_attributes = True


# ═══════ Agent Builds ═══════


class AgentGenerateRequest(BaseModel):
    service_id: str | None = None
    agent_type: str = "beacon"
    platform: str = "windows"
    arch: str = "x64"
    custom_config: dict = {}


class AgentBuildOut(BaseModel):
    id: str
    stack_id: str
    service_id: str | None
    agent_type: str
    filename: str
    platform: str
    arch: str
    c2_address: str | None
    config_hash: str | None
    file_path: str | None
    download_url: str | None
    file_size: int
    sha256: str | None
    created_at: str

    class Config:
        from_attributes = True


# ═══════ File Share ═══════


class FileShareCreate(BaseModel):
    service_id: str | None = None
    name: str = "File Share"
    base_url: str = ""
    auth_method: str = "basic"
    credentials: dict = {}


class FileShareOut(BaseModel):
    id: str
    stack_id: str
    service_id: str | None
    project_id: str | None
    name: str
    base_url: str
    auth_method: str
    credentials: dict
    status: str
    created_at: str

    class Config:
        from_attributes = True


# ═══════ Operator Access ═══════


class OperatorGrantRequest(BaseModel):
    user_id: str
    c2_username: str = ""
    c2_password: str = ""
    c2_url: str | None = None
    workstation_id: str | None = None


class OperatorAccessOut(BaseModel):
    id: str
    stack_id: str
    project_id: str
    user_id: str
    c2_username: str
    c2_url: str | None
    workstation_id: str | None
    granted_at: str
    granted_by: str | None

    class Config:
        from_attributes = True
