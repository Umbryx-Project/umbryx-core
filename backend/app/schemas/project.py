from pydantic import BaseModel, Field


class ProjectBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=500)
    status: str = "active"
    ip: str = ""
    os: str = "Linux"
    added: str
    description: str = ""


class ProjectCreate(ProjectBase):
    pass


class ProjectUpdate(BaseModel):
    name: str | None = None
    status: str | None = None
    ip: str | None = None
    os: str | None = None
    description: str | None = None
    intensity_profile: str | None = None
    env_vars: dict | None = None
    org_id: str | None = None
    # Sentinel to distinguish "not touching org_id" (org_id absent/None
    # above, handled by exclude_none) from "explicitly detach from any org"
    # (org_id sent as the literal empty string) — plain None can't carry
    # that distinction once exclude_none drops it.
    detach_org: bool = False


class Project(ProjectBase):
    id: str
    intensity_profile: str = "normal"
    org_id: str | None = None
    model_config = {"from_attributes": True}
