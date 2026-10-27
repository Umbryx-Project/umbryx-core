import logging
import os
import re
import secrets
from pathlib import Path

_logger = logging.getLogger(__name__)

_WEAK_SECRETS = {
    "",
    "change-me-in-production",
    "redteam-notes-change-me-in-production",
    "change-me-to-a-long-random-string",
    "change_me_run_openssl_rand_hex_32",
}

_SECRET_FILE = Path(os.environ.get("UPLOAD_ROOT", "/data/uploads")).parent / ".jwt_secret"


def _try_load_stored_secret(raw: str) -> str | None:
    """Read a persisted auto-generated secret if the env value is absent or weak."""
    if not _SECRET_FILE.exists():
        return None
    try:
        stored = _SECRET_FILE.read_text().strip()
    except OSError:
        return None
    if stored and (not raw or raw in _WEAK_SECRETS):
        _logger.warning(
            "JWT_SECRET not set or weak — using auto-generated secret from %s. "
            "Set JWT_SECRET in .env for production.",
            _SECRET_FILE,
        )
        return stored
    return None


def _load_jwt_secret() -> str:
    raw = os.environ.get("JWT_SECRET", "")

    # If a strong secret is provided via env, use it
    if raw and raw not in _WEAK_SECRETS and len(raw) >= 16:
        return raw

    stored = _try_load_stored_secret(raw)
    if stored:
        return stored

    if not raw or raw in _WEAK_SECRETS:
        # Generate and persist a new secret
        generated = secrets.token_hex(32)
        try:
            _SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
            _SECRET_FILE.write_text(generated)
            _SECRET_FILE.chmod(0o600)
            _logger.warning(
                "JWT_SECRET not set or is a known weak default. "
                "Auto-generated a secure secret and saved to %s. "
                "Set JWT_SECRET from that file's contents in your .env to make this permanent "
                "(the value is not logged).",
                _SECRET_FILE,
            )
        except OSError as e:
            _logger.error("Could not persist auto-generated JWT_SECRET: %s", e)
        return generated

    _logger.warning("JWT_SECRET appears weak (length < 16). Consider setting a stronger secret.")
    return raw


JWT_SECRET = _load_jwt_secret()
JWT_ALGO = "HS256"
JWT_EXPIRE_HOURS: int = int(os.environ.get("JWT_EXPIRE_HOURS", "8"))
JWT_REFRESH_EXPIRE_HOURS: int = int(os.environ.get("JWT_REFRESH_EXPIRE_HOURS", "24"))

_raw_origins = os.environ.get("CORS_ORIGINS", "")
CORS_ORIGINS: list[str] = [o.strip() for o in _raw_origins.split(",") if o.strip()]

COOKIE_NAME = "rt_auth"
COOKIE_SECURE = (
    os.environ.get(
        "COOKIE_SECURE", "true" if os.environ.get("APP_ENV") == "production" else "false"
    ).lower()
    == "true"
)

WEBHOOK_HMAC_SECRET: str = os.environ.get("WEBHOOK_HMAC_SECRET", "")

# Used to build the OIDC redirect_uri server-side (never accepted from the
# client — see routers/oidc_auth.py) — e.g. "https://umbryx.example.com".
# Falls back to the incoming request's own scheme+host when unset, which is
# fine behind a well-configured reverse proxy but should be set explicitly
# in prod so it can't be influenced by a spoofable Host header.
PUBLIC_BASE_URL: str = os.environ.get("PUBLIC_BASE_URL", "").strip().rstrip("/")

UPLOAD_ROOT = Path(os.environ.get("UPLOAD_ROOT", "/data/uploads"))
if os.environ.get("APP_ENV") != "test":
    UPLOAD_ROOT.mkdir(parents=True, exist_ok=True)

SAFE_UPLOAD_RE = re.compile(r"[^A-Za-z0-9._-]+")
DEFAULT_CATALOG_PATH = Path(__file__).parent.parent / "default_catalog.json"
