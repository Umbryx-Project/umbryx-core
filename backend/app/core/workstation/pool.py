"""Workstation pool core (2026-09-02 feature).

Pre-provision machines through PlatformOps InfraProviders, keep user SSH
public keys on profiles, and bind machines to users by appending the user's
key to the machine's ``authorized_keys`` over SSH; revoke by removing the
key line. Every grant/revoke is mirrored to the project timeline (when the
machine belongs to a project) and the audit log.

Key management on the machine uses the PLATFORM key: a dedicated keypair
generated once per deployment, whose public half is installed at
provisioning time (or supplied for manually-registered machines); the
private half (kept encrypted) authenticates the platform for
authorized_keys edits. User keys are tagged with ``umbryx:key:<id>`` so
revocation removes exactly one line and never collides with manual keys.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy.orm import Session

from ... import models
from ..crypto import decrypt_str
from ..logging_setup import get_logger

logger = get_logger(__name__)

_PLATFORM_KEY_SETTING = "workstation_platform_key"
# Never allow these characters into a key line we manage — they could
# break out of the printf format or inject extra authorized_keys lines.
_KEY_LINE_SAFE = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/= .-@:-_")


def _sanitize_key_line(value: str) -> str:
    value = (value or "").strip()
    if not value or "\n" in value or "\r" in value:
        raise ValueError("SSH public key must be a single line")
    bad = set(value) - _KEY_LINE_SAFE
    if bad:
        raise ValueError(f"SSH public key contains forbidden characters: {sorted(bad)!r}")
    return value


def normalize_public_key(public_key: str) -> str:
    """Strip a trailing comment from an OpenSSH public key line."""
    parts = _sanitize_key_line(public_key).split()
    return " ".join(parts[:2]) if len(parts) >= 2 else parts[0]


def fingerprint_of(public_key: str) -> str:
    """SHA256 fingerprint of an OpenSSH public key (best-effort, no raise)."""
    import base64
    import hashlib

    try:
        blob = normalize_public_key(public_key).split()[1]
        raw = base64.b64decode(blob, validate=True)
        return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
    except Exception:
        return ""


# ── Platform key ─────────────────────────────────────────────────────


def get_platform_key(db: Session) -> dict:
    """Return (creating on first use) the platform keypair for pool machines.

    Stored encrypted at rest in global_settings; the public half is
    installed on machines at provisioning, the private half authenticates
    the platform for authorized_keys edits.
    """
    from ..crypto import decrypt_str, encrypt_str

    item = (
        db.query(models.GlobalSetting)
        .filter(models.GlobalSetting.key == _PLATFORM_KEY_SETTING)
        .first()
    )
    if item and isinstance(item.value, dict) and item.value.get("private_key"):
        return {
            "private_key": decrypt_str(item.value["private_key"]),
            "public_key": item.value.get("public_key", ""),
        }

    private_key = Ed25519PrivateKey.generate()
    priv_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    ).decode()
    pub_line = (
        private_key.public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode()
        .strip()
    )
    if item:
        item.value = {"private_key": encrypt_str(priv_pem), "public_key": pub_line}
    else:
        db.add(
            models.GlobalSetting(
                key=_PLATFORM_KEY_SETTING,
                value={"private_key": encrypt_str(priv_pem), "public_key": pub_line},
            )
        )
    db.commit()
    logger.info("Generated workstation pool platform key")
    return {"private_key": priv_pem, "public_key": pub_line}


# ── Provisioning via PlatformOps InfraProvider ────────────────────────
#
# Every provider type that PlatformOps actually uses is wired here, each
# through its REAL creation path (no fake genericity):
#   hetzner   → CloudProviderRegistry.create_resource (ssh_key in spec)
#   proxmox   → Terraform (bpg/proxmox), same runner the legacy
#               workstation cloud path and terraform_method use
#   docker    → Docker API: pool-ssh container (image docker/images/pool-ssh)
#               with host port mapping → machine reachable over plain SSH
#   k8s       → kubectl apply Pod+Service(NodePort) with the same pool-ssh
#               image → nodeIP:nodePort SSH
#   ssh/manual→ register-manual (machine pre-exists)
# Once created, ALL types converge on plain SSH authorized_keys management
# below — the substrate doesn't matter anymore.


def _meta(ws: models.OperatorWorkstation) -> dict:
    return dict(ws.meta) if isinstance(ws.meta, dict) else {}


def _ssh_config_for(ws: models.OperatorWorkstation, db: Session) -> dict | None:
    """Connection config for managing the machine over SSH.

    Credentials priority: the machine's own stored auth (imported machines
    may carry a password or private key) → the platform key (machines the
    platform provisioned or that have the platform pubkey installed).
    """
    if not ws.access_address:
        return None
    # access_address may embed the port ("node:31234" for k8s NodePort) —
    # split it so ssh gets a plain hostname and -p.
    host = ws.access_address.strip()
    port = int(_meta(ws).get("ssh_port", 22))
    if host.count(":") == 1 and not host.startswith("["):
        h, _, p = host.rpartition(":")
        if p.isdigit():
            host, port = h, int(p)

    password = ""
    private_key = ""
    auth = _meta(ws).get("ssh_auth") or {}
    if isinstance(auth, dict) and auth.get("type") in {"password", "private_key"}:
        secret = decrypt_str(auth.get("secret") or "")
        if not secret:
            return None
        if auth["type"] == "password":
            password = secret
        else:
            private_key = secret
    else:
        private_key = get_platform_key(db)["private_key"]

    return {
        "host": host,
        "username": _meta(ws).get("ssh_user", "root"),
        "password": password,
        "private_key": private_key,
        "port": port,
        # Pool machines are ephemeral and provisioned by the platform itself;
        # trust the first host key like every other infra deployment path.
        "known_hosts_policy": "accept_new",
    }


# Public alias: the executor bridge (plugins/state) resolves workstation
# credentials through the exact same priority chain as grants/revokes.
ssh_config_for_workstation = _ssh_config_for


def probe_workstation(ws: models.OperatorWorkstation, db: Session) -> None:
    """Connectivity + credentials check. Raises RuntimeError with the
    transport error when the machine is unreachable or auth fails."""
    config = _ssh_config_for(ws, db)
    if not config:
        raise RuntimeError("Machine has no access address")
    out = _run_ssh(config, "echo umbryx-probe-ok")
    if "umbryx-probe-ok" not in (out or ""):
        raise RuntimeError("Probe returned no output — check the SSH user/shell")


def _run_ssh(config: dict, command: str) -> str:
    from ..ssh_exec import run_ssh_command

    result = run_ssh_command(config, command, 30)
    if not result.get("ok"):
        raise RuntimeError(result.get("stderr") or result.get("error") or "SSH command failed")
    return result.get("stdout") or ""


def grant_access_on_machine(
    ws: models.OperatorWorkstation, db: Session, key: models.UserSshKey
) -> None:
    """Append the user's public key to the machine's authorized_keys.

    Idempotent: skips if the exact key line (tagged umbryx:key:<id>) is
    already present.
    """
    config = _ssh_config_for(ws, db)
    if not config:
        raise RuntimeError("Machine has no access address yet")
    key_line = normalize_public_key(key.public_key)
    marker = f"umbryx:key:{key.id}"
    check = _run_ssh(config, f"grep -cF '{key_line}' ~/.ssh/authorized_keys 2>/dev/null || true")
    if check.strip() not in ("", "0"):
        return  # already granted
    _run_ssh(
        config,
        "mkdir -p ~/.ssh && chmod 700 ~/.ssh && touch ~/.ssh/authorized_keys && "
        f"chmod 600 ~/.ssh/authorized_keys && printf '%s %s\\n' '{key_line}' '{marker}' >> ~/.ssh/authorized_keys",
    )


def revoke_access_on_machine(
    ws: models.OperatorWorkstation, db: Session, key: models.UserSshKey
) -> None:
    """Remove exactly the key line tagged for this key (marker-based)."""
    config = _ssh_config_for(ws, db)
    if not config:
        raise RuntimeError("Machine has no access address yet")
    marker = f"umbryx:key:{key.id}"
    _run_ssh(
        config,
        f"sed -i '\\#{marker}#d' ~/.ssh/authorized_keys 2>/dev/null || true",
    )
