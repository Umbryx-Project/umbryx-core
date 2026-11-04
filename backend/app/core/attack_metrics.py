from ..models.attack import AttackPath, AttackPathBranch, AttackStep
from ..models.metric import MetricSnapshot
from ..models.task import Evidence, Remediation, Task
from .utils import new_id, ts_now


def calculate_path_risk(path, steps, branches=None):
    impact = getattr(path, "impact_score", None) or 50

    total = len(steps)
    verified = sum(
        1 for s in steps if (getattr(s, "node_status", None) or "") in ("verified", "successful")
    )
    likelihood = min(100, (verified / max(total, 1)) * 100) if total > 0 else 0

    max_depth = _calculate_tree_depth(steps)
    depth_bonus = min(max_depth * 3, 25)

    branch_count = (
        len(set(s.branch_name for s in steps if getattr(s, "branch_name", None))) if steps else 0
    )
    branch_bonus = min(branch_count * 5, 15)

    risk_score = min(100, impact * 0.4 + likelihood * 0.3 + depth_bonus * 0.5 + branch_bonus * 0.2)
    risk_score = round(risk_score, 1)

    return {
        "risk_score": risk_score,
        "impact_score": impact,
        "likelihood_score": likelihood,
        "depth": max_depth,
        "branch_count": branch_count,
    }


def _calculate_tree_depth(steps):
    if not steps:
        return 0

    children_map = {}
    step_ids = set()
    parent_ids = set()
    for s in steps:
        sid = s.id if hasattr(s, "id") else s.get("id", "")
        pid = s.parent_step_id if hasattr(s, "parent_step_id") else s.get("parent_step_id")
        step_ids.add(sid)
        parent_ids.add(pid)
        if pid:
            children_map.setdefault(pid, []).append(sid)

    roots = [sid for sid in step_ids if sid not in parent_ids]
    if not roots:
        roots = list(step_ids)

    max_depth = 0
    queue = [(r, 0) for r in roots]
    visited = {}
    while queue:
        node_id, depth = queue.pop(0)
        if node_id in visited and visited[node_id] >= depth:
            continue
        visited[node_id] = depth
        max_depth = max(max_depth, depth)
        for child in children_map.get(node_id, []):
            queue.append((child, depth + 1))

    return max_depth


def _calculate_depth(nodes, edges) -> int:
    if not nodes or not edges:
        return 0
    adjacency = {}
    targets = set()
    for e in edges:
        src = e.from_node if hasattr(e, "from_node") else e.get("from_node", "")
        dst = e.to_node if hasattr(e, "to_node") else e.get("to_node", "")
        adjacency.setdefault(src, []).append(dst)
        targets.add(dst)

    node_ids = {n.id if hasattr(n, "id") else n.get("id", "") for n in nodes}
    roots = node_ids - targets

    if not roots:
        return 0

    max_depth = 0
    queue = [(r, 0) for r in roots]
    visited_depths = {}

    while queue:
        node_id, depth = queue.pop(0)
        if node_id in visited_depths and visited_depths[node_id] >= depth:
            continue
        visited_depths[node_id] = depth
        max_depth = max(max_depth, depth)
        for child in adjacency.get(node_id, []):
            queue.append((child, depth + 1))

    return max_depth


def collect_metrics(db, pid: str):
    paths = (
        db.query(AttackPath).filter(AttackPath.pid == pid, AttackPath.deleted_at.is_(None)).all()
    )
    branches = (
        db.query(AttackPathBranch)
        .filter(AttackPathBranch.pid == pid, AttackPathBranch.deleted_at.is_(None))
        .all()
    )

    path_ids = {p.id for p in paths}
    status_counts: dict[str, int] = {}
    for p in paths:
        status_counts[p.status] = status_counts.get(p.status, 0) + 1

    branch_status_counts: dict[str, int] = {}
    for b in branches:
        if b.path_id in path_ids:
            branch_status_counts[b.status] = branch_status_counts.get(b.status, 0) + 1

    tasks = db.query(Task).filter(Task.pid == pid, Task.deleted_at.is_(None)).all()
    task_status_counts: dict[str, int] = {}
    for t in tasks:
        task_status_counts[t.status] = task_status_counts.get(t.status, 0) + 1

    rem = (
        db.query(Remediation).filter(Remediation.pid == pid, Remediation.deleted_at.is_(None)).all()
    )
    rem_status_counts: dict[str, int] = {}
    for r in rem:
        rem_status_counts[r.status] = rem_status_counts.get(r.status, 0) + 1

    evidence_count = db.query(Evidence).filter(Evidence.pid == pid).count()

    steps_by_path = {}
    for p in path_ids:
        steps_by_path[p] = db.query(AttackStep).filter(AttackStep.path_id == p).all()

    avg_depth = 0
    if path_ids:
        total_depth = 0
        for _p_id, p_steps in steps_by_path.items():
            total_depth += _calculate_tree_depth(p_steps)
        avg_depth = total_depth / len(path_ids)

    captured_at = ts_now()
    metrics = [
        ("attack_paths_by_status", str(len(paths)), status_counts),
        ("branches_by_status", str(len(branches)), branch_status_counts),
        ("tasks_by_status", str(len(tasks)), task_status_counts),
        ("remediations_by_status", str(len(rem)), rem_status_counts),
        ("evidence_count", str(evidence_count), {}),
        ("avg_depth", f"{avg_depth:.2f}", {}),
    ]
    for metric_key, value, dims in metrics:
        snap = MetricSnapshot(
            id=new_id("ms"),
            pid=pid,
            scope="local",
            metric_key=metric_key,
            value=value,
            dims=dims,
            captured_at=captured_at,
        )
        db.add(snap)
    db.commit()
