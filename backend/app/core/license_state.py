"""
License lifecycle: active → grace → wind-down (ФТ-15, docs/modules/LICENSING_TZ.md).

The single source of truth for "what may this instance do right now". Two
invariants hold regardless of state (see the TZ): a license state never
deletes data, and never stops or removes deployed infrastructure on its
own — only the customer tears things down.

States:
- unlicensed  — no license ever applied. Free tier, Free limits.
- active      — within the license's validity window.
- grace       — expired, but within grace_days. Full tier still works;
                a non-dismissable banner warns the admin.
- wind_down   — past the grace window. create/operate is blocked; read,
                export and teardown stay available so the customer can
                inspect, export, and wind down their own infrastructure.
                Never auto-falls to Free (C1) — holds until renewal, which
                restores the tier instantly because nothing was destroyed.

Entitlement (tier/features/limits) is read from the latest LicenseToken
only after its signature re-verifies here — the DB `claims`/`features`
columns are a display cache, not the authority, so a self-hosted admin
editing them directly changes nothing about what's actually enforced.
"""
from __future__ import annotations

import time

from sqlalchemy.orm import Session

from .. import models
from .license import (
    LicenseVerificationError,
    get_instance_license_state,
    verify_signature,
)

DEFAULT_GRACE_DAYS = 14
HEARTBEAT_STALE_SECONDS = 7 * 86400

# Notification stages, in order, keyed by days remaining until effective
# expiry. Emitted once each (deduped via InstanceLicenseState.notified_stage).
WARN_DAYS = (30, 14, 7, 1)


def _to_float(value) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _latest_token(db: Session) -> models.LicenseToken | None:
    return db.query(models.LicenseToken).order_by(models.LicenseToken.verified_at.desc()).first()


def _parse_ts(ts_str: str | None) -> float:
    if not ts_str:
        return 0.0
    from datetime import UTC, datetime

    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ"):
        try:
            return datetime.strptime(ts_str, fmt).replace(tzinfo=UTC).timestamp()
        except ValueError:
            continue
    return 0.0


def get_license_status(db: Session, now: float | None = None) -> dict:
    """Compute the instance's current lifecycle state. Pure read — never
    mutates. `now` is injectable for tests."""
    now = time.time() if now is None else now
    token = _latest_token(db)
    if token is None:
        return {
            "state": "unlicensed",
            "tier": "free",
            "grace_days": DEFAULT_GRACE_DAYS,
            "expires_at": None,
            "effective_expiry": None,
            "days_left": None,
            "grace_ends_at": None,
            "expiry_reason": "token",
            "token_days_left": None,
            "heartbeat_age_days": None,
        }

    try:
        claims = verify_signature(token.raw_token)
    except LicenseVerificationError:
        # Signature no longer verifies (tampered row, or key rotated out) —
        # treat as no valid entitlement, but still don't destroy anything.
        claims = {}

    tier = claims.get("tier", "free") if claims else "free"
    grace_days = int(claims.get("grace_days", DEFAULT_GRACE_DAYS)) if claims else DEFAULT_GRACE_DAYS

    token_expiry = _to_float(claims.get("expires_at")) if claims else 0.0

    state_row = get_instance_license_state(db)
    # Track each candidate deadline WITH its cause, so the UI can tell a real
    # "renew" situation (token near expiry) apart from the rolling heartbeat
    # window — otherwise a healthy, actively-heartbeating instance perpetually
    # looks like it "expires in ~7 days".
    candidates: dict[str, float] = {}
    if token_expiry > 0:
        candidates["token"] = token_expiry

    # A server-confirmed revocation ends the license at that moment.
    revoked_at = _parse_ts(state_row.revoked_at)
    if revoked_at > 0:
        candidates["revoked"] = revoked_at

    # Heartbeat staleness no longer shortens the license (LICENSING_REDESIGN:
    # the token is valid to its contract expiry regardless of connectivity, in
    # both online and offline installs). last_heartbeat_ok_at is kept only for
    # display; enforcement teeth come from `expires_at` and the optional soft
    # revocation signal (revoked_at) — never from connectivity. This also
    # neutralises the old client-side `license_offline` bypass, which used to
    # switch this staleness rule off.
    last_ok = _parse_ts(state_row.last_heartbeat_ok_at)
    heartbeat_age = (now - last_ok) if last_ok > 0 else None

    if candidates:
        expiry_reason = min(candidates, key=candidates.get)
        effective_expiry = candidates[expiry_reason]
    else:
        expiry_reason = "token"
        effective_expiry = token_expiry
    grace_ends_at = effective_expiry + grace_days * 86400 if effective_expiry else None

    if not claims:
        state = "wind_down"
    elif effective_expiry and now >= grace_ends_at:
        state = "wind_down"
    elif effective_expiry and now >= effective_expiry:
        state = "grace"
    else:
        state = "active"

    days_left = None
    if effective_expiry:
        days_left = int((effective_expiry - now) // 86400)

    # Days until the *token itself* expires — the true "renew" horizon, distinct
    # from the effective (possibly heartbeat-capped) days_left.
    token_days_left = int((token_expiry - now) // 86400) if token_expiry else None

    return {
        "state": state,
        "tier": tier if state != "wind_down" else "free",
        "licensed_tier": tier,
        "grace_days": grace_days,
        "expires_at": token_expiry or None,
        "effective_expiry": effective_expiry or None,
        "grace_ends_at": grace_ends_at,
        "days_left": days_left,
        # Why the license would lapse: "token" (real expiry), "heartbeat"
        # (lost contact with the license server) or "revoked".
        "expiry_reason": expiry_reason,
        "token_days_left": token_days_left,
        "heartbeat_age_days": int(heartbeat_age // 86400) if heartbeat_age is not None else None,
    }


def entitlement_active(db: Session, now: float | None = None) -> bool:
    """True when the tier's full feature set applies (active or grace)."""
    return get_license_status(db, now)["state"] in ("active", "grace", "unlicensed")


def _pending_stage(status: dict) -> str | None:
    """Which one-shot admin notification, if any, this status warrants."""
    state = status["state"]
    if state == "wind_down":
        return "wind_down"
    if state == "grace":
        return "grace"
    if state == "active" and status["days_left"] is not None:
        for d in WARN_DAYS:
            if status["days_left"] <= d:
                return f"expiring_{d}"
    return None


def notify_admins_if_needed(db: Session, now: float | None = None) -> str | None:
    """Emit a single lifecycle notification to platform admins when the
    stage changes. Called from the hourly reconciliation pass. Returns the
    stage sent, or None. Deduped via InstanceLicenseState.notified_stage."""
    from .notify import push_notification

    status = get_license_status(db, now)
    stage = _pending_stage(status)
    state_row = get_instance_license_state(db)
    if stage is None or state_row.notified_stage == stage:
        return None

    messages = {
        "wind_down": (
            "warning",
            "License expired — functionality limited",
            "The grace period has ended. Creating and operating resources is "
            "paused; you can still view, export, and wind down infrastructure. "
            "Renew the license to restore full functionality — no data was lost.",
        ),
        "grace": (
            "warning",
            "License expired — grace period active",
            f"The license expired. You have about {status['grace_days']} days "
            "before functionality is limited. Renew to avoid interruption.",
        ),
    }
    if stage.startswith("expiring_"):
        left = status["days_left"]
        payload = (
            "info",
            "License expiring soon",
            f"The license expires in about {max(left, 0)} day(s). Renew to avoid interruption.",
        )
    else:
        payload = messages[stage]

    ntype, title, body = payload
    admins = db.query(models.User).filter(models.User.role == "platform_admin").all()
    for admin in admins:
        push_notification(db, user_id=admin.id, type=ntype, title=title, body=body)
    state_row.notified_stage = stage
    db.commit()
    return stage
