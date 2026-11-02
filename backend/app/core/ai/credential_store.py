"""
Encrypted credential store for AI provider configs.

Stores provider configs in ``global_settings`` key ``ai_providers_v2``.
API keys are encrypted at rest using Fernet (via crypto.py).
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from ..crypto import decrypt_str, encrypt_str, is_encrypted
from .provider import AIProviderRegistry

logger = logging.getLogger(__name__)

_SETTING_KEY = "ai_providers_v2"
_RATE_LIMIT_WINDOW = 90  # seconds


class CredentialStore:
    """Manages AI provider configs with encrypted credentials."""

    def __init__(self, db: Session):
        self.db = db

    def _load(self) -> dict:
        from ...models import GlobalSetting

        row = self.db.query(GlobalSetting).filter(GlobalSetting.key == _SETTING_KEY).first()
        return row.value if row else {}

    def _save(self, cfg: dict) -> None:
        from ...models import GlobalSetting

        row = self.db.query(GlobalSetting).filter(GlobalSetting.key == _SETTING_KEY).first()
        if row:
            row.value = cfg
        else:
            self.db.add(GlobalSetting(key=_SETTING_KEY, value=cfg))
        self.db.commit()

    def get_config(self) -> dict:
        cfg = self._load()
        return {
            "ai_enabled": cfg.get("ai_enabled", True),
            "agent_mode": cfg.get("agent_mode", True),
            "max_tool_calls": cfg.get("max_tool_calls", 10),
            "require_confirmation_writes": cfg.get("require_confirmation_writes", True),
            "block_critical_tools": cfg.get("block_critical_tools", True),
            "providers": cfg.get("providers", []),
        }

    def save_config(self, cfg: dict) -> dict:
        current = self._load()
        current.update(
            {
                "ai_enabled": cfg.get("ai_enabled", True),
                "agent_mode": cfg.get("agent_mode", True),
                "max_tool_calls": cfg.get("max_tool_calls", 10),
                "require_confirmation_writes": cfg.get("require_confirmation_writes", True),
                "block_critical_tools": cfg.get("block_critical_tools", True),
            }
        )
        self._save(current)
        return self.get_config()

    def list_providers(self, mask: bool = True) -> list[dict]:
        cfg = self._load()
        providers = cfg.get("providers", [])
        if mask:
            return [self._mask(p) for p in providers]
        return [self._decrypt(p) for p in providers]

    def get_provider(self, provider_id: str, decrypt: bool = True) -> dict | None:
        cfg = self._load()
        for p in cfg.get("providers", []):
            if p.get("id") == provider_id:
                return self._decrypt(p) if decrypt else self._mask(p)
        return None

    def add_provider(self, provider: dict) -> dict:
        cfg = self._load()
        providers = cfg.get("providers", [])
        entry = {
            "id": provider["id"],
            "name": provider.get("name", provider["id"]),
            "provider": provider.get("provider", "openai"),
            "model": provider.get("model", ""),
            "base_url": provider.get("base_url", ""),
            "enabled": provider.get("enabled", True),
            "priority": provider.get("priority", 999),
            "skip_tools": provider.get("skip_tools", False),
            "skip_system_prompt": provider.get("skip_system_prompt", False),
            "system_prompt": provider.get("system_prompt", ""),
        }
        api_key = provider.get("api_key", "")
        if api_key:
            entry["api_key"] = encrypt_str(api_key)
        else:
            entry["api_key"] = ""
        providers.append(entry)
        cfg["providers"] = providers
        self._save(cfg)
        return self._mask(entry)

    def update_provider(self, provider_id: str, updates: dict) -> dict | None:
        cfg = self._load()
        providers = cfg.get("providers", [])
        for p in providers:
            if p.get("id") == provider_id:
                if "name" in updates:
                    p["name"] = updates["name"]
                if "provider" in updates:
                    p["provider"] = updates["provider"]
                if "model" in updates:
                    p["model"] = updates["model"]
                if "base_url" in updates:
                    p["base_url"] = updates["base_url"]
                if "enabled" in updates:
                    p["enabled"] = updates["enabled"]
                if "priority" in updates:
                    p["priority"] = updates["priority"]
                if "skip_tools" in updates:
                    p["skip_tools"] = updates["skip_tools"]
                if "skip_system_prompt" in updates:
                    p["skip_system_prompt"] = updates["skip_system_prompt"]
                if "anonymize" in updates:
                    p["anonymize"] = bool(updates["anonymize"])
                if "system_prompt" in updates:
                    p["system_prompt"] = updates["system_prompt"]
                if "api_key" in updates:
                    raw = updates["api_key"]
                    if raw and raw != "****" and not raw.startswith("****"):
                        p["api_key"] = encrypt_str(raw)
                self._save(cfg)
                return self._mask(p)
        return None

    def remove_provider(self, provider_id: str) -> bool:
        cfg = self._load()
        providers = cfg.get("providers", [])
        before = len(providers)
        cfg["providers"] = [p for p in providers if p.get("id") != provider_id]
        self._save(cfg)
        return len(cfg["providers"]) < before

    def get_next_provider(self, skip_ids: set[str] | None = None) -> dict | None:
        """Return enabled, non-rate-limited provider with lowest priority."""
        cfg = self._load()
        skip_ids = skip_ids or set()
        now = datetime.now(UTC)
        candidates = []
        for p in cfg.get("providers", []):
            if not p.get("enabled", False):
                continue
            pid = p.get("id")
            if pid in skip_ids:
                continue
            last_429 = p.get("last_429_at")
            if last_429:
                try:
                    dt = datetime.fromisoformat(last_429.replace("Z", "+00:00"))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=UTC)
                    if (now - dt).total_seconds() < _RATE_LIMIT_WINDOW:
                        continue
                except Exception:
                    pass
            candidates.append(p)
        if not candidates:
            return None
        candidates.sort(key=lambda x: x.get("priority", 999))
        return self._decrypt(candidates[0])

    def mark_429(self, provider_id: str) -> None:
        from ..utils import ts_now

        cfg = self._load()
        for p in cfg.get("providers", []):
            if p.get("id") == provider_id:
                p["last_429_at"] = ts_now()
                break
        self._save(cfg)

    def _decrypt(self, provider: dict) -> dict:
        d = dict(provider)
        if "api_key" in d and d["api_key"]:
            d["api_key"] = decrypt_str(d["api_key"])
        return d

    def _mask(self, provider: dict) -> dict:
        d = dict(provider)
        key = d.get("api_key", "")
        if key and is_encrypted(key):
            try:
                plain = decrypt_str(key)
                d["api_key"] = f"****{plain[-4:]}" if len(plain) > 4 else "****"
            except Exception:
                d["api_key"] = "****"
        elif key:
            d["api_key"] = f"****{key[-4:]}" if len(key) > 4 else "****"
        return d

    @staticmethod
    def get_provider_types() -> list[dict]:
        """Return catalog of registered provider types with schemas."""
        return [
            {
                "type": info.type,
                "display_name": info.display_name,
                "category": info.category,
                "supports_tools": info.supports_tools,
                "supports_streaming": info.supports_streaming,
                "default_models": info.default_models,
                "credentials_schema": info.credentials_schema,
            }
            for info in AIProviderRegistry.list_infos()
        ]

    def migrate_from_legacy(self) -> int:
        """Migrate providers from old ai_config to new ai_providers_v2.

        Returns number of providers migrated. Skips providers that already
        exist in the new config (matched by id or name+base_url).
        """
        from ...models import GlobalSetting

        old_row = self.db.query(GlobalSetting).filter(GlobalSetting.key == "ai_config").first()
        if not old_row or not old_row.value:
            return 0

        old_cfg = old_row.value
        old_providers = old_cfg.get("providers", [])
        if not old_providers:
            return 0

        cfg = self._load()
        new_providers = cfg.get("providers", [])
        existing_keys = {(p.get("id"), p.get("name"), p.get("base_url")) for p in new_providers}

        migrated = 0
        for p in old_providers:
            ptype = p.get("provider", "openai")
            if not AIProviderRegistry.has(ptype):
                ptype = "openai"

            pid = p.get("id") or p.get("name", "").lower().replace(" ", "-") or f"legacy-{migrated}"
            name = p.get("name", pid)
            base_url = p.get("base_url", "")

            key_tuple = (pid, name, base_url)
            if key_tuple in existing_keys:
                continue

            entry = {
                "id": pid,
                "name": name,
                "provider": ptype,
                "model": p.get("model", ""),
                "base_url": base_url,
                "enabled": p.get("enabled", True),
                "priority": p.get("priority", 999),
                "skip_tools": p.get("skip_tools", False),
            }
            api_key = p.get("api_key", "")
            if api_key and not api_key.startswith("****"):
                entry["api_key"] = encrypt_str(api_key)
            else:
                entry["api_key"] = ""

            new_providers.append(entry)
            existing_keys.add(key_tuple)
            migrated += 1

        cfg["providers"] = new_providers
        if "ai_enabled" not in cfg and "ai_enabled" in old_cfg:
            cfg["ai_enabled"] = old_cfg["ai_enabled"]
        if "agent_mode" not in cfg and "agent_mode" in old_cfg:
            cfg["agent_mode"] = old_cfg["agent_mode"]
        if "max_tool_calls" not in cfg and "max_tool_calls" in old_cfg:
            cfg["max_tool_calls"] = old_cfg["max_tool_calls"]

        self._save(cfg)
        logger.info("Migrated %d AI providers from legacy ai_config", migrated)
        return migrated
