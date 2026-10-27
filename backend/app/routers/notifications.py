from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import desc
from sqlalchemy.orm import Session

from .. import models
from ..core.deps import get_current_user, require_admin
from ..core.notifications import dispatch, get_config, save_config
from ..database import get_db
from ..models.notification import Notification

router = APIRouter(
    prefix="/api/notifications",
    tags=["notifications"],
    responses={
        400: {"description": "Bad request"},
        502: {"description": "Bad gateway"},
    },
)


class NotificationConfig(BaseModel):
    telegram: dict = {}
    slack: dict = {}
    webhook: dict = {}
    events: dict = {}


@router.get("/config")
def get_notification_config(
    db: Annotated[Session, Depends(get_db)], user: Annotated[models.User, Depends(require_admin)]
):
    return get_config(db)


@router.put("/config")
def update_notification_config(
    body: NotificationConfig,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(require_admin)],
):
    save_config(db, body.model_dump())
    return {"ok": True}


@router.post("/test")
async def test_notification(
    db: Annotated[Session, Depends(get_db)], user: Annotated[models.User, Depends(require_admin)]
):
    await dispatch(
        db,
        "test",
        "Umbryx — Test Notification",
        f"Sent by {user.username}. Notifications are working.",
    )
    return {"ok": True}


@router.get(
    "/telegram/chat-id",
    responses={400: {"description": "Bad request"}, 502: {"description": "Bad gateway"}},
)
async def get_telegram_chat_id(
    db: Annotated[Session, Depends(get_db)], user: Annotated[models.User, Depends(require_admin)]
):
    """Call getUpdates on the configured bot token to discover chat IDs from recent messages."""
    cfg = get_config(db)
    token = (cfg.get("telegram") or {}).get("token", "").strip()
    if not token:
        raise HTTPException(400, "Telegram bot token not configured")

    import asyncio
    import json
    import urllib.request

    url = f"https://api.telegram.org/bot{token}/getUpdates?limit=20&timeout=0"
    try:
        loop = asyncio.get_running_loop()
        raw = await loop.run_in_executor(
            None, lambda: urllib.request.urlopen(url, timeout=10).read()
        )
        data = json.loads(raw)
    except Exception as e:
        raise HTTPException(502, f"Telegram API error: {e}")

    if not data.get("ok"):
        raise HTTPException(
            502, f"Telegram API returned error: {data.get('description', 'unknown')}"
        )

    chats: list[dict] = []
    seen = set()
    for upd in data.get("result", []):
        msg = upd.get("message") or upd.get("channel_post") or {}
        chat = msg.get("chat", {})
        cid = chat.get("id")
        if cid and cid not in seen:
            seen.add(cid)
            chats.append(
                {
                    "id": str(cid),
                    "type": chat.get("type", ""),
                    "title": chat.get("title")
                    or chat.get("first_name")
                    or chat.get("username")
                    or str(cid),
                }
            )

    return {"chats": chats, "hint": "Send any message to your bot first if list is empty"}


# ── In-app notifications ──────────────────────────────────────────────


@router.get("")
async def list_notifications(
    limit: int = 50,
    offset: int = 0,
    unread_only: bool = False,
    db: Annotated[Session, Depends(get_db)] = None,
    user: Annotated[models.User, Depends(get_current_user)] = None,
):
    q = db.query(Notification).filter(Notification.user_id == user.id)
    if unread_only:
        q = q.filter(Notification.read == False)  # noqa: E712 — SQLAlchemy column comparison
    total = q.count()
    items = q.order_by(desc(Notification.ts)).offset(offset).limit(limit).all()
    return {
        "total": total,
        "items": [
            {
                "id": n.id,
                "ts": n.ts.isoformat() if n.ts else None,
                "type": n.type,
                "title": n.title,
                "body": n.body,
                "link": n.link,
                "read": n.read,
                "project_id": n.project_id,
            }
            for n in items
        ],
    }


@router.get("/unread-count")
async def unread_count(
    db: Annotated[Session, Depends(get_db)] = None,
    user: Annotated[models.User, Depends(get_current_user)] = None,
):
    count = (
        db.query(Notification)
        .filter(
            Notification.user_id == user.id,
            Notification.read == False,  # noqa: E712
        )
        .count()
    )
    return {"count": count}


@router.post("/{nid}/read")
async def mark_read(
    nid: str,
    db: Annotated[Session, Depends(get_db)] = None,
    user: Annotated[models.User, Depends(get_current_user)] = None,
):
    n = (
        db.query(Notification)
        .filter(Notification.id == nid, Notification.user_id == user.id)
        .first()
    )
    if not n:
        return {"error": "not found"}
    n.read = True
    n.read_ts = datetime.now(UTC)
    db.commit()
    return {"ok": True}


@router.post("/mark-all-read")
async def mark_all_read(
    db: Annotated[Session, Depends(get_db)] = None,
    user: Annotated[models.User, Depends(get_current_user)] = None,
):
    db.query(Notification).filter(
        Notification.user_id == user.id,
        Notification.read == False,  # noqa: E712
    ).update({"read": True, "read_ts": datetime.now(UTC)})
    db.commit()
    return {"ok": True}
