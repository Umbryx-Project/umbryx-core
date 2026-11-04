"""Outbound proxy for all platform egress (provisioners, DNS plugins, C2
integrations, AI, kubectl), not just the SSH executor.

Precedence: the OUTBOUND_PROXY env var (compose/secret management) wins;
otherwise the admin-managed global setting. Applied at startup by exporting
HTTP_PROXY/HTTPS_PROXY/NO_PROXY — httpx and requests honor them via
trust_env, and subprocess kubectl inherits the environment. The SSH
executor keeps its own jump-host/socks5 mechanism (OpenSSH is not
HTTP-proxy-aware); loopback and the in-cluster service range stay direct.
"""

import logging
import os

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

SETTING_KEY = "outbound_proxy"

# Never proxied: local docker socket, in-cluster services, platform itself.
_DEFAULT_NO_PROXY = "localhost,127.0.0.1,10.42.0.0/16,10.43.0.0/16,172.17.0.0/16,umbryx_backend,umbryx_frontend,umbryx_db,umbryx_redis"


def apply_outbound_proxy(db: Session | None = None) -> dict | None:
    """Export proxy env vars; returns the applied config (or None)."""
    cfg: dict = {}
    env_raw = (os.environ.get("OUTBOUND_PROXY") or "").strip()
    if env_raw:
        cfg = {"http": env_raw, "https": env_raw}
    elif db is not None:
        from ..models import GlobalSetting

        item = db.query(GlobalSetting).filter(GlobalSetting.key == SETTING_KEY).first()
        if item and isinstance(item.value, dict):
            cfg = dict(item.value)

    if not cfg.get("http") and not cfg.get("https"):
        return None

    no_proxy = cfg.get("no_proxy") or _DEFAULT_NO_PROXY
    if cfg.get("http"):
        os.environ["HTTP_PROXY"] = cfg["http"]
    if cfg.get("https"):
        os.environ["HTTPS_PROXY"] = cfg["https"]
    os.environ["NO_PROXY"] = no_proxy
    # lowercase variants — some libraries only read those
    os.environ["http_proxy"] = os.environ.get("HTTP_PROXY", "")
    os.environ["https_proxy"] = os.environ.get("HTTPS_PROXY", "")
    os.environ["no_proxy"] = no_proxy
    applied = {k: os.environ.get(k.upper(), "") for k in ("http_proxy", "https_proxy")}
    logger.info("outbound proxy applied: %s (no_proxy=%s)", applied, no_proxy)
    return applied
