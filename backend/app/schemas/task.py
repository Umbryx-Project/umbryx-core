from pydantic import BaseModel


class TaskCreate(BaseModel):
    pid: str
    title: str
    description: str = ""
    status: str = "open"
    assignee: str | None = None
    due_at: str | None = None
    priority: str = "medium"
    sla_hours: int | None = None
    source: str | None = None


class TaskUpdate(BaseModel):
    title: str | None = None
    description: str | None = None
    status: str | None = None
    assignee: str | None = None
    due_at: str | None = None
    priority: str | None = None
    sla_hours: int | None = None
    source: str | None = None
    closed_at: str | None = None
    reopened_count: int | None = None


class Task(BaseModel):
    id: str
    pid: str
    title: str
    description: str
    status: str
    assignee: str | None = None
    due_at: str | None = None
    priority: str
    sla_hours: int | None = None
    source: str | None = None
    created_by: str | None = None
    ts: str
    closed_at: str | None = None
    reopened_count: int
    deleted_at: str | None = None
    model_config = {"from_attributes": True}


class RemediationCreate(BaseModel):
    pid: str
    finding_id: str | None = None
    title: str
    description: str = ""
    status: str = "open"
    owner: str | None = None
    sla_hours: int | None = None
    due_at: str | None = None


class RemediationUpdate(BaseModel):
    finding_id: str | None = None
    title: str | None = None
    description: str | None = None
    status: str | None = None
    owner: str | None = None
    sla_hours: int | None = None
    due_at: str | None = None
    verified_by: str | None = None
    verified_at: str | None = None


class Remediation(BaseModel):
    id: str
    pid: str
    finding_id: str | None = None
    title: str
    description: str
    status: str
    owner: str | None = None
    sla_hours: int | None = None
    due_at: str | None = None
    verified_by: str | None = None
    verified_at: str | None = None
    created_by: str | None = None
    ts: str
    deleted_at: str | None = None
    model_config = {"from_attributes": True}


class EvidenceCreate(BaseModel):
    pid: str
    kind: str = "file"
    filename: str = ""
    sha256: str | None = None
    storage_ref: str | None = None
    size_bytes: int | None = None
    collected_by: str | None = None
    collected_at: str | None = None
    notes: str = ""


class Evidence(BaseModel):
    id: str
    pid: str
    kind: str
    filename: str
    sha256: str | None = None
    storage_ref: str | None = None
    size_bytes: int | None = None
    collected_by: str | None = None
    collected_at: str | None = None
    notes: str
    created_by: str | None = None
    ts: str
    model_config = {"from_attributes": True}


class IdentityCreate(BaseModel):
    pid: str
    principal: str
    domain: str = ""
    identity_type: str = "user"
    source: str | None = None
    ref_cred_id: str | None = None
    notes: str = ""


class IdentityUpdate(BaseModel):
    principal: str | None = None
    domain: str | None = None
    identity_type: str | None = None
    source: str | None = None
    ref_cred_id: str | None = None
    notes: str | None = None


class Identity(BaseModel):
    id: str
    pid: str
    principal: str
    domain: str
    identity_type: str
    source: str | None = None
    ref_cred_id: str | None = None
    notes: str
    created_by: str | None = None
    ts: str
    deleted_at: str | None = None
    model_config = {"from_attributes": True}
