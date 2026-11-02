from pydantic import BaseModel


class AttackPathNodeCreate(BaseModel):
    path_id: str
    pid: str
    kind: str = "step"
    label: str = ""
    sublabel: str = ""
    technique: str = ""
    mitre_id: str = ""
    notes: str = ""
    node_status: str = "hypothetical"
    confidence: str = "0.5"
    ref_type: str | None = None
    ref_id: str | None = None
    position: dict = {}
    host_id: str | None = None


class AttackPathNodeUpdate(BaseModel):
    kind: str | None = None
    label: str | None = None
    sublabel: str | None = None
    technique: str | None = None
    mitre_id: str | None = None
    notes: str | None = None
    node_status: str | None = None
    confidence: str | None = None
    ref_type: str | None = None
    ref_id: str | None = None
    position: dict | None = None
    host_id: str | None = None


class AttackPathNode(BaseModel):
    id: str
    path_id: str
    pid: str
    kind: str
    label: str
    sublabel: str
    technique: str
    mitre_id: str
    notes: str
    node_status: str
    confidence: str
    ref_type: str | None = None
    ref_id: str | None = None
    position: dict | None = None
    host_id: str | None = None
    created_by: str | None = None
    ts: str
    deleted_at: str | None = None
    model_config = {"from_attributes": True}


class AttackPathEdgeCreate(BaseModel):
    path_id: str
    pid: str
    from_node: str
    to_node: str
    edge_type: str = "leads_to"
    branch_id: str | None = None
    condition: str = ""
    edge_status: str = "hypothetical"
    weight: int = 0
    technique: str = ""
    mitre_id: str = ""


class AttackPathEdgeUpdate(BaseModel):
    edge_type: str | None = None
    branch_id: str | None = None
    condition: str | None = None
    edge_status: str | None = None
    weight: int | None = None
    technique: str | None = None
    mitre_id: str | None = None


class AttackPathEdge(BaseModel):
    id: str
    path_id: str
    pid: str
    from_node: str
    to_node: str
    edge_type: str
    branch_id: str | None = None
    condition: str
    edge_status: str
    weight: int
    technique: str
    mitre_id: str
    created_by: str | None = None
    ts: str
    deleted_at: str | None = None
    model_config = {"from_attributes": True}


class AttackPathBranchCreate(BaseModel):
    path_id: str
    pid: str
    name: str = ""
    root_node: str | None = None
    status: str = "hypothetical"
    owner_user_id: str | None = None
    probability: str = "0.5"
    complexity: str = "medium"
    risk_score: int | None = None
    parent_branch_id: str | None = None
    description: str = ""


class AttackPathBranchUpdate(BaseModel):
    name: str | None = None
    root_node: str | None = None
    status: str | None = None
    owner_user_id: str | None = None
    probability: str | None = None
    complexity: str | None = None
    risk_score: int | None = None
    parent_branch_id: str | None = None
    description: str | None = None


class AttackPathBranch(BaseModel):
    id: str
    path_id: str
    pid: str
    name: str
    root_node: str | None = None
    status: str
    owner_user_id: str | None = None
    probability: str
    complexity: str
    risk_score: int | None = None
    parent_branch_id: str | None = None
    description: str
    created_by: str | None = None
    ts: str
    deleted_at: str | None = None
    model_config = {"from_attributes": True}


class EntityLinkCreate(BaseModel):
    pid: str
    src_type: str
    src_id: str
    dst_type: str
    dst_id: str
    link_type: str = "relates_to"
    comment: str = ""


class EntityLinkUpdate(BaseModel):
    link_type: str | None = None
    comment: str | None = None


class EntityLink(BaseModel):
    id: str
    pid: str
    src_type: str
    src_id: str
    dst_type: str
    dst_id: str
    link_type: str
    comment: str
    created_by: str | None = None
    ts: str
    deleted_at: str | None = None
    model_config = {"from_attributes": True}


class AttackPathVersionRead(BaseModel):
    id: str
    path_id: str
    version: int
    snapshot: dict | None = None
    change_summary: str = ""
    created_by: str | None = None
    ts: str
    model_config = {"from_attributes": True}
