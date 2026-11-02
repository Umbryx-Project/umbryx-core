"""HA deployment detection and licensing.

A multi-node deployment (docs/modules/HA_DEPLOYMENT.md) is identified by
its Redis Sentinel configuration — single-node installs talk to plain
Redis and never set these variables. HA is a separately licensed option
(one license per cluster — the token lives in the shared DB — but the
cluster capability itself must be granted via the ``ha_cluster``
feature on the license).
"""

from __future__ import annotations

import os


def is_ha_deployment() -> bool:
    """True when this node is part of an HA cluster (Sentinel configured)."""
    return bool(os.environ.get("REDIS_SENTINEL_HOSTS", "").strip())


def enforce_ha_license(db) -> None:
    """Refuse to run an HA node without the ``ha_cluster`` entitlement.

    Called once at startup (after the DB is reachable): a mis-licensed HA
    node must not quietly run degraded — the whole point of a cluster is
    that every node behaves identically. Raises RuntimeError with an
    operator-actionable message; the process exits and Docker's restart
    policy keeps it in the refusal loop until a proper license is applied.
    """
    if not is_ha_deployment():
        return
    from .plan import PlanFeature, instance_has_feature

    if instance_has_feature(PlanFeature.HA_CLUSTER, db):
        return
    from .system_log import log_security

    try:
        log_security(
            db,
            "license.ha_not_licensed",
            success=False,
            message="HA deployment detected without the ha_cluster license option",
        )
        db.commit()
    except Exception:  # audit must never block the refusal itself
        pass
    raise RuntimeError(
        "This node is configured for a multi-node HA deployment (Redis "
        "Sentinel), but the installed license does not include the HA "
        "cluster option. HA is licensed separately from the base tier — "
        "request an HA-enabled license (the existing cluster activation "
        "stays valid: export the C2V and re-activate) or remove the "
        "REDIS_SENTINEL_* settings to run single-node."
    )
