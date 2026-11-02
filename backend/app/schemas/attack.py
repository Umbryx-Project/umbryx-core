from pydantic import BaseModel

from ._mixins import EmptyFkToNoneMixin


class AttackPathCreate(BaseModel):
    pid: str
    name: str = "Attack Path"
    description: str = ""


class AttackPathUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    status: str | None = None
    impact_score: float | None = None


class AttackPath(BaseModel):
    id: str
    pid: str
    name: str
    description: str | None = None
    ts: str | None = None
    status: str | None = None
    risk_score: float | None = None
    impact_score: float | None = None
    likelihood_score: float | None = None
    version: int | None = None
    created_by: str | None = None
    model_config = {"from_attributes": True}


class AttackStepCreate(EmptyFkToNoneMixin):
    path_id: str
    pid: str
    parent_step_id: str | None = None
    host_id: str | None = None
    step_order: int = 0
    node_type: str = "action"
    label: str = ""
    sublabel: str | None = None
    technique: str | None = None
    mitre_id: str | None = None
    notes: str | None = None
    node_status: str | None = "hypothetical"
    confidence: str | None = "medium"
    branch_name: str | None = None


class AttackStepUpdate(EmptyFkToNoneMixin):
    parent_step_id: str | None = None
    host_id: str | None = None
    step_order: int | None = None
    node_type: str | None = None
    label: str | None = None
    sublabel: str | None = None
    technique: str | None = None
    mitre_id: str | None = None
    notes: str | None = None
    node_status: str | None = None
    confidence: str | None = None
    branch_name: str | None = None


class AttackStep(BaseModel):
    id: str
    path_id: str
    pid: str
    parent_step_id: str | None = None
    host_id: str | None = None
    step_order: int = 0
    node_type: str = "action"
    label: str = ""
    sublabel: str | None = None
    technique: str | None = None
    mitre_id: str | None = None
    notes: str | None = None
    node_status: str | None = "hypothetical"
    confidence: str | None = "medium"
    branch_name: str | None = None
    ts: str | None = None
    model_config = {"from_attributes": True}
