from sqlalchemy import Column, ForeignKey, Integer, String, Text

from ..database import Base
from ._types import JSONB


class AttackPathVersion(Base):
    __tablename__ = "attack_path_versions"

    id = Column(String, primary_key=True)
    path_id = Column(String, ForeignKey("attack_paths.id", ondelete="CASCADE"), nullable=False)
    version = Column(Integer, nullable=False)
    snapshot = Column(JSONB, nullable=False, default=dict)
    change_summary = Column(Text, nullable=False, default="")
    created_by = Column(String, nullable=True)
    ts = Column(String, nullable=False)


class AttackPath(Base):
    __tablename__ = "attack_paths"

    id = Column(String, primary_key=True)
    pid = Column(String, ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String, nullable=False, default="Attack Path")
    description = Column(Text, nullable=False, default="")
    ts = Column(String, nullable=False)
    status = Column(String, nullable=False, default="draft", server_default="draft")
    risk_score = Column(Integer, nullable=True)
    impact_score = Column(Integer, nullable=True)
    likelihood_score = Column(Integer, nullable=True)
    version = Column(Integer, nullable=False, default=1, server_default="1")
    created_by = Column(String, nullable=True)
    updated_at = Column(String, nullable=True)
    deleted_at = Column(String, nullable=True)


class AttackStep(Base):
    __tablename__ = "attack_steps"

    id = Column(String, primary_key=True)
    path_id = Column(
        String, ForeignKey("attack_paths.id", ondelete="CASCADE"), nullable=False, index=True
    )
    pid = Column(String, nullable=False, index=True)
    parent_step_id = Column(
        String, ForeignKey("attack_steps.id", ondelete="SET NULL"), nullable=True, index=True
    )
    host_id = Column(String, ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True)
    step_order = Column(Integer, nullable=False, default=0)
    node_type = Column(String, nullable=False, default="host")
    label = Column(String, nullable=False, default="")
    sublabel = Column(String, nullable=False, default="")
    technique = Column(String, nullable=False, default="")
    mitre_id = Column(String, nullable=False, default="")
    notes = Column(Text, nullable=False, default="")
    node_status = Column(String, nullable=True, default="hypothetical")
    confidence = Column(String, nullable=True, default="medium")
    branch_name = Column(String, nullable=True)
    ts = Column(String, nullable=False)


class AttackPathNode(Base):
    __tablename__ = "attack_path_nodes"

    id = Column(String, primary_key=True)
    path_id = Column(String, ForeignKey("attack_paths.id", ondelete="CASCADE"), nullable=False)
    pid = Column(String, nullable=False, index=True)
    kind = Column(String, nullable=False, default="step")
    label = Column(String, nullable=False, default="")
    sublabel = Column(String, nullable=False, default="")
    technique = Column(String, nullable=False, default="")
    mitre_id = Column(String, nullable=False, default="")
    notes = Column(Text, nullable=False, default="")
    node_status = Column(String, nullable=False, default="hypothetical")
    confidence = Column(String, nullable=False, default="0.5")
    ref_type = Column(String, nullable=True)
    ref_id = Column(String, nullable=True)
    position = Column(JSONB, nullable=False, default=dict)
    host_id = Column(String, ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True)
    created_by = Column(String, nullable=True)
    ts = Column(String, nullable=False)
    deleted_at = Column(String, nullable=True)


class AttackPathEdge(Base):
    __tablename__ = "attack_path_edges"

    id = Column(String, primary_key=True)
    path_id = Column(String, ForeignKey("attack_paths.id", ondelete="CASCADE"), nullable=False)
    pid = Column(String, nullable=False, index=True)
    from_node = Column(
        String, ForeignKey("attack_path_nodes.id", ondelete="CASCADE"), nullable=False
    )
    to_node = Column(String, ForeignKey("attack_path_nodes.id", ondelete="CASCADE"), nullable=False)
    edge_type = Column(String, nullable=False, default="leads_to")
    branch_id = Column(
        String, ForeignKey("attack_path_branches.id", ondelete="SET NULL"), nullable=True
    )
    condition = Column(Text, nullable=False, default="")
    edge_status = Column(String, nullable=False, default="hypothetical")
    weight = Column(Integer, nullable=False, default=0)
    technique = Column(String, nullable=False, default="")
    mitre_id = Column(String, nullable=False, default="")
    created_by = Column(String, nullable=True)
    ts = Column(String, nullable=False)
    deleted_at = Column(String, nullable=True)


class AttackPathBranch(Base):
    __tablename__ = "attack_path_branches"

    id = Column(String, primary_key=True)
    path_id = Column(String, ForeignKey("attack_paths.id", ondelete="CASCADE"), nullable=False)
    pid = Column(String, nullable=False, index=True)
    name = Column(String, nullable=False, default="")
    root_node = Column(
        String, ForeignKey("attack_path_nodes.id", ondelete="SET NULL"), nullable=True
    )
    status = Column(String, nullable=False, default="hypothetical")
    owner_user_id = Column(String, nullable=True)
    probability = Column(String, nullable=False, default="0.5")
    complexity = Column(String, nullable=False, default="medium")
    risk_score = Column(Integer, nullable=True)
    parent_branch_id = Column(
        String, ForeignKey("attack_path_branches.id", ondelete="SET NULL"), nullable=True
    )
    description = Column(Text, nullable=False, default="")
    created_by = Column(String, nullable=True)
    ts = Column(String, nullable=False)
    deleted_at = Column(String, nullable=True)
