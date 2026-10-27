"""
Online license heartbeat (ФТ-6, docs/modules/LICENSING_TZ.md).

Runs once per 24h per cluster (main.py's _license_heartbeat_loop, guarded
by the "license_heartbeat" leader-election role). Licensing is per
self-hosted instance, not per Organization (see core/license.py's module
docstring) — this loop does exactly one heartbeat call for the whole
instance, not one per org.

Eligible only if the instance has ever been licensed at all (at least one
LicenseToken row exists) and hasn't opted into the offline channel
(InstanceLicenseState.license_offline). An instance whose tier was set
manually via PATCH /api/marketplace/plans/{org_id} and never went through
a signed license is left alone entirely: heartbeat renews an existing
license, it doesn't police plans that were never licensed via a token in
the first place.

The License Server (ФТ-10) lives in a separate repo, umbryx-license-server
(never a subdirectory of this one — it holds the private signing key),
deployed at https://update.umbryx.pro.
"""
from __future__ import annotations

import os

import httpx
from sqlalchemy.orm import Session

from .. import models
from .hwid import current_hwid_hashes
from .instance_identity import instance_public_key_b64, sign_with_instance_key
from .license import (
    LicenseVerificationError,
    apply_license_token,
    get_fingerprint,
    get_instance_license_state,
    get_or_create_install_uuid,
)
from .logging_setup import get_logger
from .system_log import log_security
from .utils import ts_now

logger = get_logger(__name__)

LICENSE_SERVER_URL = os.environ.get("LICENSE_SERVER_URL", "https://update.umbryx.pro")
HEARTBEAT_TIMEOUT = 10


def run_heartbeat(db: Session, client: httpx.Client) -> str:
    """One heartbeat attempt for the whole instance. Returns one of
    "not_licensed", "offline_channel", "renewed", "inactive", or
    "unreachable".

    This no longer downgrades anything itself. Lapsing is governed by the
    lifecycle (core/license_state.py): a successful renew clears any
    revocation and refreshes the last-ok clock; a server-confirmed
    "inactive" stamps revoked_at (soft revocation — the normal grace period
    starts from now, no instant cut-off); an unreachable server does nothing,
    since the license is valid to its contract expiry regardless of
    connectivity (LICENSING_REDESIGN)."""
    never_licensed = not db.query(models.LicenseToken).first()
    if never_licensed and get_instance_license_state(db).license_offline:
        # Deliberately-offline and never licensed: nothing to poll for —
        # the .lic file is the only activation path there.
        return "not_licensed"

    state = get_instance_license_state(db)
    if state.license_offline:
        return "offline_channel"

    fingerprint = get_fingerprint(db)
    # Signed online check-in (LICENSING_REDESIGN Phase 3): prove possession of
    # this instance's key over a fresh timestamp so the License Server can
    # authenticate us (and bind the key trust-on-first-use), instead of treating
    # the fingerprint alone as the credential.
    import time as _time

    ts = _time.time()
    signature = sign_with_instance_key(db, f"{fingerprint}:{ts}".encode())
    payload = {
        "fingerprint": fingerprint,
        "instance_pubkey": instance_public_key_b64(db),
        "hwid": current_hwid_hashes(get_or_create_install_uuid(db)),
        "ts": ts,
        "signature": signature,
    }
    try:
        resp = client.post(
            f"{LICENSE_SERVER_URL}/v1/heartbeat",
            json=payload,
            timeout=HEARTBEAT_TIMEOUT,
        )
        resp.raise_for_status()
        body = resp.json()
    except Exception as exc:
        logger.info("[license-heartbeat] License Server unreachable: %s", exc)
        return "unreachable"

    token = body.get("token")
    if not token:
        if never_licensed:
            # Expected pre-activation state: the vendor simply hasn't bound
            # this instance's c2v to a license yet. Poll quietly — no grace
            # clock (there is nothing to lapse), no security-event noise.
            logger.debug("[license-heartbeat] no license bound yet — waiting")
            return "awaiting_license"
        # A definitive "no active license" from a server we DID reach —
        # start the grace clock now rather than cutting off immediately.
        state.revoked_at = ts_now()
        state.updated_at = ts_now()
        db.commit()
        log_security(
            db,
            "license.reported_inactive",
            success=False,
            message="License heartbeat: server reports no active license — grace period started",
        )
        return "inactive"

    try:
        apply_license_token(db, token)
    except LicenseVerificationError as exc:
        logger.warning("[license-heartbeat] server returned an invalid token: %s", exc)
        return "unreachable"
    return "activated" if never_licensed else "renewed"


def run_heartbeat_pass(db: Session) -> dict:
    with httpx.Client() as client:
        outcome = run_heartbeat(db, client)
    return (
        {outcome: 1}
        if outcome not in ("not_licensed", "offline_channel", "awaiting_license")
        else {"awaiting_license": 1} if outcome == "awaiting_license" else {}
    )
