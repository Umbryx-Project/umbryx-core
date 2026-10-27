"""
Signed license-token verification (ФТ-5) and per-install fingerprint
(ФТ-4). See docs/modules/LICENSING_TZ.md and docs/modules/MONETIZATION.md
for the design this implements.

Licensing is per SELF-HOSTED INSTANCE, not per Organization — a single
install may model several internal Organizations (e.g. an MSSP's
different clients), but they all share one license, one fingerprint, and
one InstanceLicenseState. OrganizationPlan rows are a per-org *cache* kept
in sync with that single instance-wide entitlement (see
core/plan.py's get_instance_entitlement/sync_all_orgs_to_entitlement) so
the many org-scoped enforcement checks added in ФТ-1 (has_feature(org_id,
...), check_member_limit(org_id, ...), etc.) don't need to change.

The Ed25519 PUBLIC key below is a fixed source constant, never read from
an env var or the database: if it were configurable, a self-hosted admin
with DB/env access could swap it for their own keypair and self-sign an
unlimited license, which defeats the entire point of licensing a
self-hosted product. The matching PRIVATE key lives only on the License
Server (separate repo, umbryx-license-server) and must never be committed
to this repository.

Fingerprint = sha256(install_uuid + hardware_id). install_uuid is a
random value generated once and persisted in this instance's own DB
(GlobalSetting) — cheap, but a raw DB/disk copy duplicates it 1:1, so it
can't stand alone as a clone-resistant identifier. hardware_id
(get_hardware_id) is layered on top specifically to survive that case:
it looks for identifiers a hypervisor or cloud platform assigns to the
*running instance* rather than anything stored on the cloned disk itself
(cloud metadata instance-id, or the DMI/SMBIOS system UUID that VMware/
Proxmox/KVM/Hyper-V/VirtualBox all regenerate on a proper VM clone) —
degrades gracefully to "" (install_uuid alone) wherever neither is
reachable, rather than failing.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy.orm import Session

from .. import models

# Public half of the License Server's Ed25519 signing keypair (ФТ-10,
# separate repo: umbryx-license-server). The matching PRIVATE key lives only
# there and must never be committed to this repo.
#
# This is a FIXED source constant on purpose — it is deliberately NOT read
# from an env var, a config file, or the database. If it were configurable
# at deploy time, a self-hosted admin (who controls their own env/DB) could
# point it at their own keypair and self-sign an unlimited license, which
# defeats the entire point of licensing a self-hosted product. Anti-forgery
# rests on the Ed25519 signature over this specific key, so the key must not
# be swappable by anyone but us, at source. The only legitimate way to change
# it is a real key rotation: edit the constant below (add the new key to
# TRUSTED_PUBLIC_KEYS for an overlap window) and ship a new build.
#
# A self-hosted operator can of course still patch the compiled code — that
# is inherent to any on-prem software and is out of the threat model; the
# bar here is that no configuration, env var, or DB row can change it.
PUBLIC_KEY_B64 = "tD24kAJsiHQIACqZZoJYd8S7t1sEkGjyKjV0MTQQ2PQ"

# During a key rotation, add the incoming key here alongside the current one
# for an overlap window (both are accepted), then remove the retired key in a
# later build. Source-only, never env/DB — same reasoning as above.
ADDITIONAL_TRUSTED_KEYS: tuple[str, ...] = ()


def trusted_public_keys() -> tuple[str, ...]:
    """Base64url public key(s) this instance accepts license signatures from.
    Fixed at source (PUBLIC_KEY_B64 + ADDITIONAL_TRUSTED_KEYS) —
    intentionally not configurable at runtime, so a key can't be swapped via
    env/DB to self-sign licenses. Read at call time so a key rotation only
    needs the constants above changed (and tests can patch PUBLIC_KEY_B64)."""
    return (PUBLIC_KEY_B64, *ADDITIONAL_TRUSTED_KEYS)


_INSTALL_UUID_KEY = "install_uuid"
_INSTANCE_LICENSE_STATE_ID = "instance"


def _verified_at_now() -> str:
    """Microsecond-precision timestamp for LicenseToken.verified_at.

    Plain ts_now() (second precision) lets two tokens applied within the
    same second get equal verified_at strings, making "ORDER BY
    verified_at DESC LIMIT 1" (get_instance_entitlement,
    license_reconciliation._latest_token) resolve ties on an SQL engine's
    unspecified tiebreak instead of actually picking the latest one —
    caught by heartbeat renewal tests applying two tokens back to back."""
    import datetime as _dt

    return _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class LicenseVerificationError(Exception):
    """Raised with a user-facing reason — signature/expiry/fingerprint
    all report distinct messages so an admin uploading a bad file knows
    what actually failed."""


def _b64d(s: str) -> bytes:
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def get_or_create_install_uuid(db: Session) -> str:
    row = db.get(models.GlobalSetting, _INSTALL_UUID_KEY)
    if row and row.value.get("uuid"):
        return row.value["uuid"]
    new_uuid = uuid.uuid4().hex
    if row:
        row.value = {"uuid": new_uuid}
    else:
        row = models.GlobalSetting(key=_INSTALL_UUID_KEY, value={"uuid": new_uuid})
        db.add(row)
    db.commit()
    return new_uuid


_DMI_PRODUCT_UUID_PATH = "/sys/class/dmi/id/product_uuid"
_METADATA_TIMEOUT = 0.3  # these should answer near-instantly if present at all


def _aws_instance_id() -> str:
    import httpx

    token = httpx.put(
        "http://169.254.169.254/latest/api/token",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
        timeout=_METADATA_TIMEOUT,
    ).text
    r = httpx.get(
        "http://169.254.169.254/latest/meta-data/instance-id",
        headers={"X-aws-ec2-metadata-token": token},
        timeout=_METADATA_TIMEOUT,
    )
    return r.text.strip()


def _gcp_instance_id() -> str:
    import httpx

    r = httpx.get(
        "http://metadata.google.internal/computeMetadata/v1/instance/id",
        headers={"Metadata-Flavor": "Google"},
        timeout=_METADATA_TIMEOUT,
    )
    return r.text.strip()


def _azure_vm_id() -> str:
    import httpx

    r = httpx.get(
        "http://169.254.169.254/metadata/instance/compute/vmId"
        "?api-version=2021-02-01&format=text",
        headers={"Metadata": "true"},
        timeout=_METADATA_TIMEOUT,
    )
    return r.text.strip()


def _hetzner_instance_id() -> str:
    import httpx

    r = httpx.get(
        "http://169.254.169.254/hetzner/v1/metadata/instance-id", timeout=_METADATA_TIMEOUT
    )
    return r.text.strip()


def _digitalocean_droplet_id() -> str:
    import httpx

    r = httpx.get(
        "http://169.254.169.254/metadata/v1/id", timeout=_METADATA_TIMEOUT
    )
    return r.text.strip()


def _dmi_system_uuid() -> str:
    with open(_DMI_PRODUCT_UUID_PATH) as f:
        return f.read().strip()


def get_hardware_id() -> str:
    """Best-effort identifier that survives a disk-level VM clone —
    unlike install_uuid (a DB row) or /etc/machine-id (a file on the same
    disk), both of which a raw disk/volume copy duplicates 1:1. This looks
    instead for identifiers the hypervisor or cloud platform assigns to
    the *running instance*, never stored on the cloned disk itself:

    1. Cloud instance metadata ID (AWS/GCP/Azure/Hetzner/DigitalOcean) —
       assigned by the provider at instance creation.
    2. DMI/SMBIOS system UUID (/sys/class/dmi/id/product_uuid) — set by
       the hypervisor (VMware/Proxmox/KVM/Hyper-V/VirtualBox all
       regenerate this on a proper "Clone VM" operation, precisely
       because it's meant to be unique per running VM) or burned into
       physical hardware by the OEM on bare metal.

    Returns "" if none are reachable/readable (wrong permissions, no
    network route to the metadata service, bare metal without DMI access,
    etc.) — the fingerprint then falls back to install_uuid alone, same
    as before this was added. Never raises: a customer on an environment
    where none of this is available must still get a working, if weaker,
    fingerprint rather than a crash.
    """
    for getter in (
        _aws_instance_id,
        _gcp_instance_id,
        _azure_vm_id,
        _hetzner_instance_id,
        _digitalocean_droplet_id,
        _dmi_system_uuid,
    ):
        try:
            value = getter()
            if value:
                return value
        except Exception:
            continue
    return ""


def compute_fingerprint(install_uuid: str, hardware_id: str = "") -> str:
    return hashlib.sha256(f"{install_uuid}:{hardware_id}".encode()).hexdigest()


def get_fingerprint(db: Session) -> str:
    """Recomputed fresh on every call, never cached in the DB — caching
    the hardware_id half anywhere on the same disk that gets cloned would
    defeat the entire point (see get_hardware_id's docstring)."""
    return compute_fingerprint(get_or_create_install_uuid(db), get_hardware_id())


# ── Offline activation handshake (LICENSING_REDESIGN Phase 2) ────────────────

_PENDING_ACTIVATION_KEY = "pending_activation"


def _get_pending_activation(db: Session) -> dict | None:
    row = db.get(models.GlobalSetting, _PENDING_ACTIVATION_KEY)
    return dict(row.value) if row and row.value else None


def _set_pending_activation(db: Session, value: dict | None) -> None:
    row = db.get(models.GlobalSetting, _PENDING_ACTIVATION_KEY)
    if row:
        row.value = value or {}
    else:
        row = models.GlobalSetting(key=_PENDING_ACTIVATION_KEY, value=value or {})
        db.add(row)
    db.commit()


def build_activation_request(db: Session) -> dict:
    """Build the C2V (client-to-vendor) activation request an air-gapped
    instance exports: its hwid (hashed, two classes), its public key, and a
    fresh nonce (stored as pending so the imported license can be tied back to
    this request). No network needed. See LICENSING_REDESIGN."""
    import secrets

    from .hwid import current_hwid_hashes
    from .instance_identity import instance_public_key_b64

    install_uuid = get_or_create_install_uuid(db)
    nonce = secrets.token_urlsafe(24)
    _set_pending_activation(db, {"nonce": nonce, "created_at": time.time()})
    return {
        "format_version": 1,
        "product": "umbryx",
        "install_uuid": install_uuid,
        "fingerprint": get_fingerprint(db),  # legacy single hash, for convenience
        "hwid": current_hwid_hashes(install_uuid),
        "instance_pubkey": instance_public_key_b64(db),
        "nonce": nonce,
        "created_at": time.time(),
    }


def _verify_binding(db: Session, claims: dict, fingerprint: str) -> None:
    """Verify a license is bound to THIS installation. Prefers the new fuzzy
    hwid binding (+ instance key + handshake nonce); falls back to the legacy
    single fingerprint for older tokens. Raises LicenseVerificationError."""
    from .instance_identity import instance_public_key_b64

    bound_pub = claims.get("instance_pubkey")
    if bound_pub and bound_pub != instance_public_key_b64(db):
        raise LicenseVerificationError(
            "This license is bound to a different instance key (re-activation required)"
        )

    bound_hwid = claims.get("hwid")
    if bound_hwid:
        from .hwid import current_hwid_hashes, match_hwid

        result = match_hwid(
            bound_hwid, current_hwid_hashes(get_or_create_install_uuid(db)),
            claims.get("hwid_policy"),
        )
        if not result["ok"]:
            raise LicenseVerificationError(
                f"Hardware identity mismatch — {result['reason']} (re-activation required)"
            )
    elif claims.get("fingerprint") != fingerprint:
        raise LicenseVerificationError(
            "This license was issued for a different installation (fingerprint mismatch)"
        )

    # Offline-handshake anti-replay: if the license echoes a nonce and we have a
    # pending request, they must match (stops importing a .lic minted for a
    # different request/box). Absent pending -> accept (hwid+key already bind it).
    nonce = claims.get("nonce")
    if nonce:
        pending = _get_pending_activation(db)
        if pending and pending.get("nonce") and pending["nonce"] != nonce:
            raise LicenseVerificationError(
                "This license does not match this installation's activation request"
            )


def get_instance_license_state(db: Session) -> models.InstanceLicenseState:
    row = db.get(models.InstanceLicenseState, _INSTANCE_LICENSE_STATE_ID)
    if row:
        return row
    from ..core.utils import ts_now

    row = models.InstanceLicenseState(
        id=_INSTANCE_LICENSE_STATE_ID,
        license_offline=False,
        last_heartbeat_ok_at=None,
        updated_at=ts_now(),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def verify_signature(raw_token: str) -> dict:
    """Check structure and signature only, returning the signed claims.
    Expiry is deliberately not checked here: the lifecycle
    (core/license_state.py) needs the claims of an expired token to run
    its grace period. Token format: "<b64url(payload_json)>.<b64url(sig)>".
    """
    try:
        payload_b64, sig_b64 = raw_token.strip().split(".")
        payload_bytes = _b64d(payload_b64)
        signature = _b64d(sig_b64)
    except Exception as exc:
        raise LicenseVerificationError("Malformed license file") from exc

    verified = False
    for key_b64 in trusted_public_keys():
        try:
            Ed25519PublicKey.from_public_bytes(_b64d(key_b64)).verify(signature, payload_bytes)
            verified = True
            break
        except (InvalidSignature, ValueError):
            continue
    if not verified:
        raise LicenseVerificationError(
            "Invalid signature — this license wasn't signed by the key this build "
            "trusts. Re-issue the license from the License Server whose "
            "GET /admin/public-key matches this build's PUBLIC_KEY_B64."
        )

    try:
        claims = json.loads(payload_bytes)
    except Exception as exc:
        raise LicenseVerificationError("Malformed license payload") from exc
    if not isinstance(claims, dict):
        raise LicenseVerificationError("Malformed license payload")
    return claims


def verify_license_token(raw_token: str, expected_fingerprint: str) -> dict:
    """Full check for applying a token: signature, expiry, and binding to
    this installation's fingerprint. Raises LicenseVerificationError with a
    specific user-facing reason."""
    claims = verify_signature(raw_token)

    if claims.get("expires_at", 0) < time.time():
        raise LicenseVerificationError("License has expired")

    if claims.get("fingerprint") != expected_fingerprint:
        raise LicenseVerificationError(
            "This license was issued for a different installation (fingerprint mismatch)"
        )

    return claims


def apply_license_token(db: Session, raw_token: str) -> dict:
    """Verify *raw_token* against this instance's fingerprint, persist it
    as a LicenseToken row, and sync every Organization's OrganizationPlan
    to match (see core/plan.py's sync_all_orgs_to_entitlement — the
    license covers the whole instance, not one org). Shared by the manual
    upload endpoint (routers/license_admin.py) and the online heartbeat
    loop (license_heartbeat.py) — both channels apply a token the same
    way, only how the token was obtained differs. Raises
    LicenseVerificationError on any verification failure.
    """
    from ..core.plan import TIER_LIMITS, sync_all_orgs_to_entitlement
    from ..core.utils import new_id, ts_now

    fingerprint = get_fingerprint(db)
    # Signature + expiry (shared with verify_license_token), then binding — which
    # now prefers fuzzy hwid + instance key + handshake nonce, falling back to
    # the legacy single fingerprint for older tokens.
    claims = verify_signature(raw_token)
    if claims.get("expires_at", 0) < time.time():
        raise LicenseVerificationError("License has expired")
    _verify_binding(db, claims, fingerprint)

    tier = claims.get("tier", "free")
    if tier not in TIER_LIMITS:
        raise LicenseVerificationError(f"License names an unknown tier: {tier}")

    now = ts_now()
    db.add(
        models.LicenseToken(
            id=new_id("lic"),
            raw_token=raw_token,
            fingerprint=fingerprint,
            tier=tier,
            features=claims.get("features") or TIER_LIMITS[tier]["features"],
            claims=claims,
            verified_at=_verified_at_now(),
            expires_at=str(claims.get("expires_at", "")),
        )
    )
    db.commit()

    sync_all_orgs_to_entitlement(db)

    state = get_instance_license_state(db)
    state.last_heartbeat_ok_at = now
    state.revoked_at = None
    state.notified_stage = None
    state.retention_floor_days = _raise_retention_floor(
        state.retention_floor_days,
        claims.get("retention_days", TIER_LIMITS[tier]["retention_days"]),
    )
    state.updated_at = now
    db.commit()

    # Consume the offline-activation request once its license is applied.
    _set_pending_activation(db, None)

    return claims


def _raise_retention_floor(current: int | None, granted: int | None) -> int | None:
    if granted is None:
        return current
    if current == -1 or granted == -1:
        return -1
    return max(current or 0, granted)


