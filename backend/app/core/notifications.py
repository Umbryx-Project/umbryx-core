"""
Notification dispatcher — sends alerts to Telegram, Slack, or a generic webhook.

Settings are loaded from global_settings key "notifications" on each call
so changes take effect immediately without restart.
"""

import asyncio
import logging

_CONTENT_TYPE_JSON = "application/json"

logger = logging.getLogger(__name__)

_SETTING_KEY = "notifications"


def _load_config(db) -> dict:
    from ..models import GlobalSetting

    row = db.query(GlobalSetting).filter(GlobalSetting.key == _SETTING_KEY).first()
    return row.value if row else {}


def get_config(db) -> dict:
    return _load_config(db)


def save_config(db, cfg: dict) -> None:
    from ..models import GlobalSetting

    row = db.query(GlobalSetting).filter(GlobalSetting.key == _SETTING_KEY).first()
    if row:
        row.value = cfg
    else:
        db.add(GlobalSetting(key=_SETTING_KEY, value=cfg))
    db.commit()


def _event_enabled(cfg: dict, event: str) -> bool:
    return bool(cfg.get("events", {}).get(event, True))


async def _send_telegram(token: str, chat_id: str, text: str) -> bool:
    try:
        from .ssrf_guard import validate_outbound_url

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        validate_outbound_url(url)
        await _post_json(url, {"chat_id": chat_id, "text": text, "parse_mode": "HTML"})
        return True
    except Exception as e:
        logger.warning("[notifications] Telegram error: %s", e)
        return False


async def _send_slack(webhook_url: str, text: str) -> bool:
    try:
        from .ssrf_guard import validate_outbound_url

        validate_outbound_url(webhook_url)
        await _post_json(webhook_url, {"text": text})
        return True
    except Exception as e:
        logger.warning("[notifications] Slack error: %s", e)
        return False


async def _post_json(url: str, data: dict, timeout: int = 10) -> None:
    """POST via the egress factory: proxy-pool route "notifications" wins,
    global env proxy is the floor, else direct."""
    from .database import SessionLocal
    from .net import egress_async_client

    db = SessionLocal()
    try:
        client = egress_async_client("notifications", None, db=db, timeout=timeout)
    finally:
        db.close()
    try:
        await client.post(url, json=data, headers={"Content-Type": _CONTENT_TYPE_JSON})
    finally:
        await client.aclose()


async def _send_webhook(url: str, payload: dict) -> bool:
    try:
        from .ssrf_guard import validate_outbound_url

        validate_outbound_url(url)
        await _post_json(url, payload)
        return True
    except Exception as e:
        logger.warning("[notifications] Webhook error: %s", e)
        return False


async def dispatch(db, event: str, title: str, body: str, payload: dict | None = None) -> None:
    """Fire-and-forget notification. Never raises."""
    try:
        cfg = _load_config(db)
        if not cfg:
            return
        if not _event_enabled(cfg, event):
            return

        text = f"<b>{title}</b>\n{body}"
        full_payload = {"event": event, "title": title, "body": body, **(payload or {})}

        tasks = []
        tg = cfg.get("telegram") or {}
        if tg.get("enabled") and tg.get("token") and tg.get("chat_id"):
            tasks.append(_send_telegram(tg["token"], tg["chat_id"], text))

        sl = cfg.get("slack") or {}
        if sl.get("enabled") and sl.get("webhook_url"):
            tasks.append(_send_slack(sl["webhook_url"], f"{title}\n{body}"))

        wh = cfg.get("webhook") or {}
        if wh.get("enabled") and wh.get("url"):
            tasks.append(_send_webhook(wh["url"], full_payload))

        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    except Exception as e:
        logger.warning("[notifications] dispatch error: %s", e)


def dispatch_sync(db, event: str, title: str, body: str, payload: dict | None = None) -> None:
    """Schedule notification as a background asyncio task (call from sync context or after await)."""
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(dispatch(db, event, title, body, payload))
    except RuntimeError:
        pass  # no running loop — skip silently
