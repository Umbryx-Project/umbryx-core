from __future__ import annotations

from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from .. import models
from ..core.crypto import decrypt_str, encrypt_str
from ..core.logging_setup import get_logger
from ..core.utils import new_id, ts_now

logger = get_logger(__name__)

REGISTRIES_KEY = "image_registries"


def _settings_key(org_id: str | None) -> str:
    """Platform-wide registries (org_id=None, legacy/pre-org data) live
    under the bare key; each organization gets its own isolated list under
    a composed key, so editing one org's registries can never leak into or
    overwrite another org's (2026-08-18)."""
    return REGISTRIES_KEY if org_id is None else f"{REGISTRIES_KEY}:org:{org_id}"


def _mask(r: dict) -> dict:
    entry = dict(r)
    if entry.get("password"):
        entry["password"] = "***"
    return entry


def list_image_registries(db: Session, org_id: str | None = None) -> list[dict]:
    key = _settings_key(org_id)
    item = db.query(models.GlobalSetting).filter(models.GlobalSetting.key == key).first()
    if not item or not isinstance(item.value, dict):
        return []
    return [_mask(r) for r in item.value.get("registries", [])]


def get_image_registry_raw(reg_id: str, db: Session, org_id: str | None = None) -> dict | None:
    key = _settings_key(org_id)
    item = db.query(models.GlobalSetting).filter(models.GlobalSetting.key == key).first()
    if not item or not isinstance(item.value, dict):
        return None
    for r in item.value.get("registries", []):
        if r.get("id") == reg_id:
            result = dict(r)
            if result.get("password"):
                result["password"] = decrypt_str(result["password"])
            return result
    return None


def add_image_registry(
    name: str,
    url: str,
    username: str,
    password: str,
    db: Session,
    org_id: str | None = None,
    is_default: bool = False,
) -> dict:
    key = _settings_key(org_id)
    item = db.query(models.GlobalSetting).filter(models.GlobalSetting.key == key).first()
    if not item:
        item = models.GlobalSetting(key=key, value={"registries": []})
        db.add(item)
    if not isinstance(item.value, dict):
        item.value = {"registries": []}

    reg = {
        "id": new_id("reg"),
        "name": name,
        "url": url.strip().rstrip("/"),
        "username": username,
        "password": encrypt_str(password) if password else "",
        "is_default": bool(is_default),
        "created_at": ts_now(),
    }
    item.value["registries"].append(reg)
    flag_modified(item, "value")
    db.commit()
    return _mask(reg)


def delete_image_registry(reg_id: str, db: Session, org_id: str | None = None) -> bool:
    key = _settings_key(org_id)
    item = db.query(models.GlobalSetting).filter(models.GlobalSetting.key == key).first()
    if not item or not isinstance(item.value, dict):
        return False
    before = len(item.value.get("registries", []))
    item.value["registries"] = [
        r for r in item.value.get("registries", []) if r.get("id") != reg_id
    ]
    if len(item.value["registries"]) == before:
        return False
    flag_modified(item, "value")
    db.commit()
    return True
