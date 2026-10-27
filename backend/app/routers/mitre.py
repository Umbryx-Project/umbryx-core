from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import models
from ..core.access import check_pid_access
from ..core.deps import get_current_user
from ..database import get_db
from .kb import MITRE_CATEGORY

router = APIRouter(tags=["mitre"])

TACTIC_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


def _kb_to_technique(article: models.KBArticle) -> dict:
    mid = article.tags[0] if article.tags else ""
    # title format: "T1234 — Name"  or just the title
    name = article.title
    if " — " in name:
        name = name.split(" — ", 1)[1]
    tactic = ""
    for tag in article.tags or []:
        # tactic stored as snake_case tag, e.g. "lateral_movement"
        candidate = tag.replace("_", " ").title()
        if candidate in TACTIC_ORDER:
            tactic = candidate
            break
    return {"id": mid, "tactic": tactic, "name": name, "kb_id": article.id}


def _index_attack_steps(steps) -> tuple[set, dict]:
    used_ids: set[str] = set()
    used_names: dict[str, list[dict]] = {}
    for s in steps:
        mid = (s.mitre_id or "").strip().upper()
        if mid:
            used_ids.add(mid)
        tech = (s.technique or "").strip()
        if tech:
            key = tech.lower()
            if key not in used_names:
                used_names[key] = []
            used_names[key].append({"step_id": s.id, "label": s.label, "technique": tech})
    return used_ids, used_names


@router.get("/api/projects/{pid}/purple")
def get_purple_view(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    """Purple-team summary: which MITRE techniques this engagement actually
    exercised, from every source that carries them, plus the defender-side
    timeline for detection-engineering review.

    Sources:
    - AttackStep.mitre_id (planned/executed attack path)
    - NetworkEdge.extra_json.mitre_techniques (graph edges tagged by Smart
      Build — cred validation, bulk exec, pivots, C2)
    - KBArticle MITRE entries provide tactic mapping where seeded

    Deliberately read-only aggregation: this is the same data the red-side
    views show, re-cut for the blue team.
    """
    check_pid_access(db, pid, user, "findings.read")

    steps = db.query(models.AttackStep).filter(models.AttackStep.pid == pid).all()
    edges = db.query(models.NetworkEdge).filter(models.NetworkEdge.pid == pid).all()

    kb_articles = (
        db.query(models.KBArticle)
        .filter(
            models.KBArticle.pid.is_(None),
            models.KBArticle.category == MITRE_CATEGORY,
        )
        .all()
    )
    tactic_by_id: dict[str, str] = {}
    for a in kb_articles:
        t = _kb_to_technique(a)
        if t["id"]:
            tactic_by_id.setdefault(t["id"].upper(), t["tactic"])

    techniques: dict[str, dict] = {}

    def _record(tid: str, source: str, label: str):
        tid = tid.strip().upper()
        if not tid:
            return
        entry = techniques.setdefault(
            tid,
            {
                "id": tid,
                "tactic": tactic_by_id.get(tid, ""),
                "steps": 0,
                "edges": 0,
                "labels": [],
            },
        )
        entry[source] += 1
        if label and label not in entry["labels"] and len(entry["labels"]) < 10:
            entry["labels"].append(label)

    for s in steps:
        _record(s.mitre_id or "", "steps", s.label or s.technique or "")
    for e in edges:
        for tid in (e.extra_json or {}).get("mitre_techniques", []) or []:
            _record(tid, "edges", e.label or e.source)

    technique_list = sorted(
        techniques.values(),
        key=lambda t: (TACTIC_ORDER.index(t["tactic"]) if t["tactic"] in TACTIC_ORDER else 99, t["id"]),
    )

    events = (
        db.query(models.TimelineEvent)
        .filter(models.TimelineEvent.pid == pid)
        .order_by(models.TimelineEvent.ts.desc())
        .limit(100)
        .all()
    )
    timeline = [
        {
            "ts": e.ts,
            "entity": e.entity,
            "action": e.action,
            "label": e.label[:160],
            "username": e.username,
        }
        for e in events
    ]

    findings = (
        db.query(models.Finding)
        .filter(models.Finding.pid == pid, models.Finding.deleted_at.is_(None))
        .all()
    )
    severity_counts: dict[str, int] = {}
    for f in findings:
        severity_counts[f.severity or "unknown"] = severity_counts.get(f.severity or "unknown", 0) + 1

    by_tactic: dict[str, int] = {}
    for t in technique_list:
        key = t["tactic"] or "Unmapped"
        by_tactic[key] = by_tactic.get(key, 0) + 1

    return {
        "techniques": technique_list,
        "tactic_order": TACTIC_ORDER,
        "by_tactic": by_tactic,
        "stats": {
            "techniques_total": len(technique_list),
            "mapped_to_tactic": sum(1 for t in technique_list if t["tactic"]),
            "steps_total": len(steps),
            "steps_with_mitre": sum(1 for s in steps if s.mitre_id),
            "tagged_edges": sum(
                1 for e in edges if (e.extra_json or {}).get("mitre_techniques")
            ),
            "findings_total": len(findings),
            "findings_by_severity": severity_counts,
            "timeline_events": len(timeline),
        },
        "timeline": timeline,
    }
@router.get("/api/projects/{pid}/mitre/coverage")
def get_mitre_coverage(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "findings.read")

    kb_articles = (
        db.query(models.KBArticle)
        .filter(
            models.KBArticle.pid is None,
            models.KBArticle.category == MITRE_CATEGORY,
        )
        .all()
    )

    techniques = [_kb_to_technique(a) for a in kb_articles]
    kb_seeded = len(techniques) > 0
    steps = db.query(models.AttackStep).filter(models.AttackStep.pid == pid).all()
    used_ids, used_names = _index_attack_steps(steps)

    enriched = []
    for t in techniques:
        tid = t["id"].upper()
        name_key = t["name"].lower()
        used = tid in used_ids or any(name_key in k or k in name_key for k in used_names)
        enriched.append({**t, "used": used})

    unmapped = []
    known_ids = {t["id"].upper() for t in techniques}
    for s in steps:
        mid = (s.mitre_id or "").strip().upper()
        if mid and mid not in known_ids:
            unmapped.append({"id": mid, "name": s.technique or "", "label": s.label})

    return {
        "techniques": enriched,
        "tactic_order": TACTIC_ORDER,
        "kb_seeded": kb_seeded,
        "stats": {
            "total_techniques": len(techniques),
            "covered": sum(1 for t in enriched if t["used"]),
            "steps_with_mitre": sum(1 for s in steps if s.mitre_id),
            "steps_total": len(steps),
        },
        "unmapped": unmapped,
    }
