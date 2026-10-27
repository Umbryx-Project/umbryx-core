"""
Instance-wide licensing admin API (ФТ-4/5/6, docs/modules/LICENSING_TZ.md).

Licensing is per self-hosted instance, not per Organization — see
core/license.py's module docstring. Platform-admin only, same bar as the
other instance-wide config endpoints (e.g. /api/system/oidc-providers),
not org-admin: an org owner/admin manages their own org's members/teams/
SSO, but the instance's license is a platform-operator concern.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .. import models
from ..core.deps import get_current_user, require_admin
from ..core.license import (
    LicenseVerificationError,
    apply_license_token,
    get_fingerprint,
    get_instance_license_state,
    trusted_public_keys,
)
from ..core.plan import get_instance_entitlement
from ..core.utils import ts_now
from ..database import get_db

router = APIRouter(prefix="/api/system/license", tags=["license"])


class LicenseUploadBody(BaseModel):
    token: str


class LicenseChannelBody(BaseModel):
    offline: bool


@router.get("/state")
def get_license_lifecycle_state(
    db: Annotated[Session, Depends(get_db)],
    _user: Annotated[models.User, Depends(get_current_user)],
):
    """Lifecycle state plus the current entitlement (tier / features /
    limits) — available to any authenticated user, so the frontend can gate
    UI (hide/lock tier-only features) and show the expiry banner. Licensing
    is instance-wide (every org mirrors it), so this single call is enough;
    it deliberately omits the admin-only fingerprint/heartbeat details."""
    from ..core.license_state import get_license_status
    from ..core.plan import get_instance_entitlement

    status = get_license_status(db)
    ent = get_instance_entitlement(db)
    return {
        "state": status["state"],
        "days_left": status["days_left"],
        "grace_days": status["grace_days"],
        "expiry_reason": status["expiry_reason"],
        "token_days_left": status["token_days_left"],
        "heartbeat_age_days": status["heartbeat_age_days"],
        "tier": ent["tier"],
        "features": [str(f) for f in ent["features"]],
        "limits": {
            "max_members": ent["max_members"],
            "max_infra_instances": ent["max_infra_instances"],
            "max_workstations": ent["max_workstations"],
            "retention_days": ent["retention_days"],
        },
    }


@router.get("/fingerprint")
def get_license_fingerprint(
    db: Annotated[Session, Depends(get_db)],
    _admin: Annotated[models.User, Depends(require_admin)],
):
    # trusted_public_keys lets an operator diff this install's accepted
    # signing key(s) against their License Server's GET /admin/public-key
    # when a license is rejected as "invalid signature".
    from ..core.instance_identity import instance_public_key_b64

    return {
        "fingerprint": get_fingerprint(db),
        "trusted_public_keys": trusted_public_keys(),
        # This instance's public key ("soft electronic key"); the License Server
        # binds the license to it during activation (LICENSING_REDESIGN).
        "instance_pubkey": instance_public_key_b64(db),
    }


@router.get("/activation-request")
def download_activation_request(
    db: Annotated[Session, Depends(get_db)],
    _admin: Annotated[models.User, Depends(require_admin)],
):
    """Export the C2V activation request for offline (air-gap) activation: the
    instance's hwid + public key + a fresh nonce. Carry it to the License
    Server, get back a signed .lic, and upload it via /upload. No network
    needed on this instance. See LICENSING_REDESIGN."""
    import json

    from fastapi.responses import Response

    from ..core.license import build_activation_request

    req = build_activation_request(db)
    return Response(
        content=json.dumps(req, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="umbryx-activation-request.c2v.json"'},
    )


@router.post("/check")
def check_for_license_now(
    db: Annotated[Session, Depends(get_db)],
    _admin: Annotated[models.User, Depends(require_admin)],
):
    """Run one online license check immediately (the same pass the daily
    loop does). For an instance still waiting for its first license this is
    the 'Check now' button: the moment the vendor binds the c2v to a
    license, this pull activates it — no files, no keys."""
    from ..core.license_heartbeat import run_heartbeat_pass

    outcome = run_heartbeat_pass(db)
    return {"checked": True, "outcome": outcome}


@router.post("/upload", status_code=201)
def upload_license(
    body: LicenseUploadBody,
    db: Annotated[Session, Depends(get_db)],
    _admin: Annotated[models.User, Depends(require_admin)],
):
    try:
        claims = apply_license_token(db, body.token)
    except LicenseVerificationError as exc:
        raise HTTPException(402, str(exc)) from exc

    latest = (
        db.query(models.LicenseToken).order_by(models.LicenseToken.verified_at.desc()).first()
    )
    return {
        "tier": claims.get("tier"),
        "features": claims.get("features"),
        "verified_at": latest.verified_at if latest else None,
        "expires_at": latest.expires_at if latest else None,
    }


@router.get("/status")
def get_license_status(
    db: Annotated[Session, Depends(get_db)],
    _admin: Annotated[models.User, Depends(require_admin)],
):
    from ..core.license_state import get_license_status

    latest = (
        db.query(models.LicenseToken).order_by(models.LicenseToken.verified_at.desc()).first()
    )
    state = get_instance_license_state(db)
    entitlement = get_instance_entitlement(db)
    status = get_license_status(db)
    channel = "offline" if state.license_offline else "online"
    return {
        "tier": entitlement["tier"],
        "state": status["state"],
        "days_left": status["days_left"],
        "grace_days": status["grace_days"],
        "effective_expiry": status["effective_expiry"],
        "grace_ends_at": status["grace_ends_at"],
        "expiry_reason": status["expiry_reason"],
        "token_days_left": status["token_days_left"],
        "heartbeat_age_days": status["heartbeat_age_days"],
        "source": "license_token" if latest else "manual",
        "channel": channel,
        "verified_at": latest.verified_at if latest else None,
        "expires_at": latest.expires_at if latest else None,
        "last_heartbeat_ok_at": state.last_heartbeat_ok_at,
    }


@router.patch("/channel")
def set_license_channel(
    body: LicenseChannelBody,
    db: Annotated[Session, Depends(get_db)],
    _admin: Annotated[models.User, Depends(require_admin)],
):
    """Opt the instance into the offline license channel (no automatic
    online heartbeat) or back into online. Air-gapped deployments aren't
    special-cased here — they simply never reach the internet in the
    first place, so the heartbeat loop fails closed for them the same way
    network trouble would for anyone else (see
    core/license_heartbeat.py's grace-period handling)."""
    state = get_instance_license_state(db)
    state.license_offline = body.offline
    state.updated_at = ts_now()
    db.commit()
    return {"license_offline": state.license_offline}
