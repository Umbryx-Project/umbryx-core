"""CSV export endpoints for hosts, findings, and credentials."""

import csv
import io
from typing import Annotated

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from .. import models
from ..core.access import check_pid_access
from ..core.deps import get_current_user
from ..database import get_db

router = APIRouter(prefix="/api/projects/{pid}/export", tags=["export"])


def _csv_response(filename: str, rows: list[list]) -> StreamingResponse:
    buf = io.StringIO()
    writer = csv.writer(buf)
    for row in rows:
        writer.writerow(row)
    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/hosts.csv")
def export_hosts(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "hosts.read")
    hosts = db.query(models.Host).filter(models.Host.pid == pid).all()
    # Host.notes (a single free-text column) was replaced by full Notes
    # attached via Note.host_id — join their titles/content per host so
    # the CSV keeps a "notes" column with equivalent information.
    notes_by_host: dict[str, list[str]] = {}
    for n in (
        db.query(models.Note.host_id, models.Note.title, models.Note.content)
        .filter(
            models.Note.pid == pid,
            models.Note.host_id.isnot(None),
            models.Note.deleted_at.is_(None),
        )
        .all()
    ):
        notes_by_host.setdefault(n.host_id, []).append(
            f"{n.title}: {n.content}" if n.content else n.title
        )
    rows = [
        ["ip", "hostname", "os", "status", "role", "domain", "ports", "services", "tags", "notes"]
    ]
    for h in hosts:
        rows.append(
            [
                h.ip,
                h.hostname,
                h.os,
                h.status,
                h.role,
                h.domain,
                "; ".join(h.ports or []),
                "; ".join(h.services or []),
                "; ".join(h.tags or []),
                " | ".join(notes_by_host.get(h.id, [])),
            ]
        )
    return _csv_response(f"hosts_{pid[:8]}.csv", rows)


@router.get("/findings.csv")
def export_findings(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    check_pid_access(db, pid, user, "findings.read")
    findings = db.query(models.Finding).filter(models.Finding.pid == pid).all()
    rows = [
        ["title", "severity", "cvss", "cve", "status", "description", "proof", "recommendation"]
    ]
    for f in findings:
        rows.append(
            [
                f.title,
                f.severity,
                f.cvss,
                f.cve,
                f.status,
                f.description,
                f.proof,
                f.recommendation,
            ]
        )
    return _csv_response(f"findings_{pid[:8]}.csv", rows)


@router.get("/creds.csv")
def export_creds(
    pid: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    # Credentials export never includes the secret/password column
    check_pid_access(db, pid, user, "credentials.read")
    creds = db.query(models.Cred).filter(models.Cred.pid == pid).all()
    rows = [["username", "service", "host", "domain", "type", "cracked", "tags", "notes"]]
    for c in creds:
        rows.append(
            [
                c.username,
                c.service,
                c.host,
                c.domain,
                c.type,
                str(c.cracked),
                "; ".join(c.tags or []),
                c.notes,
            ]
        )
    return _csv_response(f"creds_{pid[:8]}.csv", rows)
