from __future__ import annotations

from enum import StrEnum

from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .. import models
from ..database import get_db


class PlanFeature(StrEnum):
    INFRA_LIFECYCLE = "infra_lifecycle"
    WORKSTATIONS = "workstations"
    DNS_MANAGEMENT = "dns_management"
    CLOUD_PROVIDER_TIER1 = "cloud_provider_tier1"  # Hetzner / DigitalOcean / Vultr — Pro+
    CLOUD_PROVIDER_TIER2 = "cloud_provider_tier2"  # AWS / Azure / GCP / Proxmox — Enterprise
    VPN_GENERATION = "vpn_generation"
    PLUGIN_UPLOAD = "plugin_upload"
    CUSTOM_TEMPLATES = "custom_templates"
    ADVANCED_AUDIT = "advanced_audit"
    API_ACCESS = "api_access"
    MULTIPLE_ORGS = "multiple_orgs"  # >1 Organization per instance (MSSP) — Pro+
    SSO = "sso"
    PRIORITY_SUPPORT = "priority_support"


# Порядок тиров для сравнений "минимум такой-то тир" (см. tier_at_least) —
# для ограничений вида "начиная с Pro", которые неудобно выражать как
# отдельный бинарный флаг.
TIER_ORDER = ["free", "team", "pro", "enterprise"]

# Типы cloud/DNS-провайдеров (InfraProvider.type) по тирам — см.
# docs/modules/LICENSING_TZ.md ФТ-1/ФТ-2 и карту тиров в MONETIZATION.md.
CLOUD_TIER1_TYPES = {"hetzner", "digitalocean", "vultr"}
CLOUD_TIER2_TYPES = {"aws", "azure", "gcp", "proxmox"}
DNS_TIER2_TYPES = {"route53", "route53_dns"}
# docker/ssh_host/kubernetes намеренно не гейтятся: docker — core-функция
# на всех тирах (MONETIZATION.md), kubernetes не описан в карте тиров вообще
# — не гейтим по недокументированному предположению.


TIER_LIMITS = {
    # Free is the Community Edition tier: no deployment of any kind. Both
    # provisioning limits are 0 rather than a small allowance — CE is "bring
    # your own infrastructure", so there is no trial instance to meter.
    # What stays open on Free is the operator's own machines: attacker-SSH
    # targets (unlimited, project-bound, not gated by any PlanFeature) and
    # pool machines registered manually over SSH, together with pool access
    # grant/revoke — keeping those open is what keeps action logging and the
    # audit trail meaningful, which must never sit behind a paywall.
    "free": {
        # 2026-10-09: raised 3→5 members and 30→90 days retention — the old
        # free tier was tighter than the free alternatives, hurting adoption
        # without adding a meaningful upgrade incentive.
        "max_members": 5,
        "max_infra_instances": 0,
        "max_workstations": 0,
        "retention_days": 90,
        "features": [],
    },
    "team": {
        "max_members": 10,
        "max_infra_instances": -1,
        "max_workstations": 5,
        "retention_days": 90,
        "features": [
            PlanFeature.INFRA_LIFECYCLE,
            PlanFeature.WORKSTATIONS,
            PlanFeature.CUSTOM_TEMPLATES,
            PlanFeature.API_ACCESS,
            PlanFeature.DNS_MANAGEMENT,
            PlanFeature.VPN_GENERATION,
        ],
    },
    "pro": {
        "max_members": -1,
        "max_infra_instances": -1,
        "max_workstations": -1,
        "retention_days": 365,
        "features": [
            PlanFeature.INFRA_LIFECYCLE,
            PlanFeature.WORKSTATIONS,
            PlanFeature.DNS_MANAGEMENT,
            PlanFeature.CLOUD_PROVIDER_TIER1,
            PlanFeature.PLUGIN_UPLOAD,
            PlanFeature.CUSTOM_TEMPLATES,
            PlanFeature.ADVANCED_AUDIT,
            PlanFeature.API_ACCESS,
            PlanFeature.VPN_GENERATION,
            PlanFeature.MULTIPLE_ORGS,
        ],
    },
    "enterprise": {
        "max_members": -1,
        "max_infra_instances": -1,
        "max_workstations": -1,
        # -1 = custom/unlimited: Enterprise retention is a contractual,
        # per-customer policy (MONETIZATION.md: "кастомные retention
        # политики"), not an automatic tier default — the retention
        # cleanup job (core/audit_retention.py) skips -1 entirely rather
        # than guessing at an unlimited numeric window.
        "retention_days": -1,
        "features": [f for f in PlanFeature],
    },
}


def get_org_plan(org_id: str, db: Session) -> dict:
    plan = (
        db.query(models.OrganizationPlan).filter(models.OrganizationPlan.org_id == org_id).first()
    )
    if plan:
        return {
            "tier": plan.tier,
            "max_members": plan.max_members,
            "max_infra_instances": plan.max_infra_instances,
            "max_workstations": plan.max_workstations,
            "retention_days": plan.retention_days,
            "features": plan.features if isinstance(plan.features, list) else [],
        }
    # No OrganizationPlan row yet (org never touched by
    # marketplace_update_plan/ensure_org_plan) — TIER_LIMITS["free"] alone
    # has no "tier" key, which used to raise KeyError in any caller that
    # reads plan["tier"] (e.g. tier_at_least) on a brand-new org.
    return {"tier": "free", **TIER_LIMITS["free"]}


def get_instance_entitlement(db: Session) -> dict:
    """What the self-hosted instance's current license actually grants —
    the single source every org's OrganizationPlan should mirror (see
    docs/modules/LICENSING_TZ.md: licensing is per-instance, not per-org —
    a self-hosted install may model several internal Organizations for,
    say, an MSSP's different clients, but they all share one license).
    Entitlement is read from the latest token's *signature-verified*
    claims, not the DB `claims`/`features` columns (those are a display
    cache a self-hosted admin could edit). Expiry does NOT zero this to
    Free: the lifecycle (core/license_state.py) governs grace/wind-down and
    the request gate governs what wind-down blocks — entitlement stays at
    the licensed tier so a lapsed license can be renewed back to full
    function instantly without ever having destroyed anything (C1). Falls
    back to Free only when nothing was ever licensed or the signature no
    longer verifies."""
    from .license import LicenseVerificationError, verify_signature

    latest = db.query(models.LicenseToken).order_by(models.LicenseToken.verified_at.desc()).first()
    if latest:
        try:
            claims = verify_signature(latest.raw_token)
        except LicenseVerificationError:
            claims = None
        if claims:
            tier = claims.get("tier", "free")
            tier_defaults = TIER_LIMITS.get(tier, TIER_LIMITS["free"])
            return {
                "tier": tier,
                "max_members": claims.get("max_members", tier_defaults["max_members"]),
                "max_infra_instances": claims.get(
                    "max_infra_instances", tier_defaults["max_infra_instances"]
                ),
                "max_workstations": claims.get(
                    "max_workstations", tier_defaults["max_workstations"]
                ),
                "retention_days": claims.get("retention_days", tier_defaults["retention_days"]),
                "features": list(claims.get("features") or tier_defaults["features"]),
            }
    return {"tier": "free", **TIER_LIMITS["free"]}


def sync_all_orgs_to_entitlement(db: Session) -> None:
    """Writes the instance's current entitlement (get_instance_entitlement)
    into every Organization's OrganizationPlan row. Called after a license
    is applied (manual upload or online heartbeat renewal) — the license is
    instance-wide, so every org on this installation gets the same tier/
    features/limits, not just whichever org happened to receive the token
    upload request."""
    from ..core.utils import ts_now

    entitlement = get_instance_entitlement(db)
    now = ts_now()
    for org in db.query(models.Organization).all():
        plan = ensure_org_plan(org.id, db)
        plan.tier = entitlement["tier"]
        plan.max_members = entitlement["max_members"]
        plan.max_infra_instances = entitlement["max_infra_instances"]
        plan.max_workstations = entitlement["max_workstations"]
        plan.retention_days = entitlement["retention_days"]
        plan.features = list(entitlement["features"])
        plan.updated_at = now
    db.commit()


def has_feature(org_id: str, feature: PlanFeature, db: Session) -> bool:
    plan = get_org_plan(org_id, db)
    return feature in plan.get("features", [])


def instance_has_feature(feature: PlanFeature, db: Session) -> bool:
    """Feature check against the instance-wide entitlement, for platform-admin
    endpoints that aren't scoped to a single org (DNS at the platform level,
    plugin install, etc.). Unlicensed instances are Free and get nothing
    above Free — the licensed monetization tier is what opens these."""
    return str(feature) in [str(f) for f in get_instance_entitlement(db)["features"]]


def tier_at_least(org_id: str, min_tier: str, db: Session) -> bool:
    plan = get_org_plan(org_id, db)
    try:
        return TIER_ORDER.index(plan["tier"]) >= TIER_ORDER.index(min_tier)
    except ValueError:
        return False


def check_provider_type_allowed(org_id: str, provider_type: str, db: Session) -> tuple[bool, str]:
    """Whether an org's plan allows registering/using this InfraProvider.type.

    Returns (allowed, reason) — reason is a user-facing message when not
    allowed, empty string otherwise. Providers not listed in any tier set
    (docker, ssh_host, kubernetes, dns adapters other than route53*) are
    allowed on every tier — see the comment above CLOUD_TIER1_TYPES.
    """
    if provider_type in CLOUD_TIER2_TYPES:
        if not has_feature(org_id, PlanFeature.CLOUD_PROVIDER_TIER2, db):
            return False, f"Provider type '{provider_type}' requires the Enterprise plan"
    elif provider_type in CLOUD_TIER1_TYPES:
        if not has_feature(org_id, PlanFeature.CLOUD_PROVIDER_TIER1, db):
            return False, f"Provider type '{provider_type}' requires the Pro plan or higher"
    elif provider_type in DNS_TIER2_TYPES:
        if not tier_at_least(org_id, "pro", db):
            return False, f"DNS provider '{provider_type}' requires the Pro plan or higher"
    return True, ""


def check_member_limit(org_id: str, db: Session) -> bool:
    plan = get_org_plan(org_id, db)
    limit = plan["max_members"]
    if limit == -1:
        return True
    count = (
        db.query(models.OrganizationMember)
        .filter(models.OrganizationMember.org_id == org_id)
        .count()
    )
    return count < limit


def check_infra_limit(org_id: str, db: Session) -> bool:
    plan = get_org_plan(org_id, db)
    limit = plan["max_infra_instances"]
    if limit == -1:
        return True
    from ..models.infra_v2 import InfraStack

    # Count by the org's own projects, not by org members' project
    # memberships (a member could belong to projects in other orgs, which
    # would miscount). No bare except: a counting error must not silently
    # read as "under limit" and wave the request through.
    count = (
        db.query(InfraStack)
        .filter(
            InfraStack.project_id.in_(
                db.query(models.Project.id).filter(models.Project.org_id == org_id)
            ),
            InfraStack.status != "destroyed",
        )
        .count()
    )
    return count < limit


def over_limit_stack_ids(org_id: str, db: Session) -> set[str]:
    """Stack ids beyond the org's max_infra_instances (D1). After a tier
    downgrade the org may hold more stacks than the new plan allows; the
    oldest `limit` keep operating, the newest excess become read-only +
    teardown-only. Returns the excess set (empty when unlimited)."""
    plan = get_org_plan(org_id, db)
    limit = plan["max_infra_instances"]
    if limit == -1:
        return set()
    from ..models.infra_v2 import InfraStack

    rows = (
        db.query(InfraStack.id)
        .filter(
            InfraStack.project_id.in_(
                db.query(models.Project.id).filter(models.Project.org_id == org_id)
            ),
            InfraStack.status != "destroyed",
        )
        .order_by(InfraStack.created_at.asc())
        .all()
    )
    return {r[0] for r in rows[limit:]} if limit >= 0 else set()


def over_limit_workstation_ids(org_id: str, db: Session) -> set[str]:
    """Workstation ids beyond the org's max_workstations (D1) — same
    oldest-keep, newest-excess-read-only rule as over_limit_stack_ids."""
    plan = get_org_plan(org_id, db)
    limit = plan["max_workstations"]
    if limit == -1:
        return set()
    rows = (
        db.query(models.OperatorWorkstation.id)
        .filter(
            models.OperatorWorkstation.project_id.in_(
                db.query(models.Project.id).filter(models.Project.org_id == org_id)
            ),
            models.OperatorWorkstation.status != "destroyed",
        )
        .order_by(models.OperatorWorkstation.created_at.asc())
        .all()
    )
    return {r[0] for r in rows[limit:]} if limit >= 0 else set()


def check_org_limit(db: Session) -> bool:
    """Whether another Organization may be created on this instance. Multiple
    orgs (the MSSP / multi-tenant use case) require MULTIPLE_ORGS (Pro+);
    without it the instance is capped at a single organization. Instance-wide
    check — the new org has no plan of its own yet.

    Bypassed under APP_ENV=test: the suite runs on one shared in-memory DB
    where orgs accumulate across every module, so a hard cap of 1 would break
    unrelated tests. The real logic is covered by a test that overrides
    APP_ENV."""
    import os

    if os.environ.get("APP_ENV") == "test":
        return True
    if instance_has_feature(PlanFeature.MULTIPLE_ORGS, db):
        return True
    return db.query(models.Organization).count() < 1


def check_workstation_limit(org_id: str, db: Session, adding: int = 1) -> bool:
    """Whether the org may create `adding` more workstations under its plan's
    max_workstations. Counts existing non-destroyed workstations across the
    org's projects. Free tier's limit is 0, so this is the gate that stops a
    Free instance from spinning up unlimited workstations."""
    plan = get_org_plan(org_id, db)
    limit = plan["max_workstations"]
    if limit == -1:
        return True
    project_ids = db.query(models.Project.id).filter(models.Project.org_id == org_id)
    count = (
        db.query(models.OperatorWorkstation)
        .filter(
            models.OperatorWorkstation.project_id.in_(project_ids),
            models.OperatorWorkstation.status != "destroyed",
        )
        .count()
    )
    return count + adding <= limit


def ensure_org_plan(org_id: str, db: Session) -> models.OrganizationPlan:
    plan = (
        db.query(models.OrganizationPlan).filter(models.OrganizationPlan.org_id == org_id).first()
    )
    if plan:
        return plan
    from ..core.utils import new_id, ts_now

    # A brand-new org on an already-licensed instance inherits the current
    # instance-wide entitlement immediately, not a hardcoded Free — the
    # license covers the whole install, not individual orgs (see
    # get_instance_entitlement). Falls back to Free defaults on its own
    # when nothing has ever been licensed.
    defaults = get_instance_entitlement(db)
    plan = models.OrganizationPlan(
        id=new_id("op"),
        org_id=org_id,
        tier=defaults["tier"],
        max_members=defaults["max_members"],
        max_infra_instances=defaults["max_infra_instances"],
        max_workstations=defaults["max_workstations"],
        retention_days=defaults["retention_days"],
        features=list(defaults["features"]),
        created_at=ts_now(),
        updated_at=ts_now(),
    )
    db.add(plan)
    db.commit()
    db.refresh(plan)
    return plan


# ── Edition / feature gating as a router dependency ──────────────────
# Deployment modules (infra lifecycle, workstation provisioning) are whole
# routers rather than single endpoints, so gating them handler-by-handler
# across ~30 routes is the kind of coverage that rots the moment someone
# adds a route. Instead the router declares the feature it needs once, and
# this dependency classifies each request the same way the license gate
# does (core/license_gate.py): reads, exports and teardown stay available
# so an unlicensed instance can still inspect and wind down what it has,
# while creating and operating is what costs a license.
def require_instance_feature(feature: PlanFeature, detail: str = ""):
    """Router/endpoint dependency: 402 on mutating requests unless the
    instance's license grants `feature`. Safe and teardown requests pass."""
    message = detail or (
        f"This feature ({feature}) is not included in your license. "
        "It is part of Umbryx Enterprise Edition — reads and teardown remain available."
    )

    def dependency(request: Request, db: Session = Depends(get_db)) -> None:
        from .license_gate import SAFE_METHODS, classify

        if request.method in SAFE_METHODS:
            return
        if classify(request.method, request.url.path) == "teardown":
            return
        if not instance_has_feature(feature, db):
            raise HTTPException(402, message)

    return dependency


# ── Extended membership roles ────────────────────────────────────────
# MONETIZATION.md puts the client-facing review roles at Team and above,
# while the base roles stay free on every tier because RBAC is a security
# feature. These three are the paid ones.
EXTENDED_MEMBER_ROLES = frozenset({"reviewer", "analyst", "observer"})


def instance_tier_at_least(min_tier: str, db: Session) -> bool:
    """Tier comparison against the instance's signed entitlement.

    The org-scoped `tier_at_least` reads OrganizationPlan, a row the
    self-hosted customer owns and can edit; this reads the verified license
    claims instead (see get_instance_entitlement).

    A tier comparison rather than a PlanFeature, deliberately: a license
    token carries an explicit `features` list, so adding a new flag would
    silently withdraw the capability from every token already issued —
    tokens in the field predate it. `tier` is always present, which is
    also how MONETIZATION.md states this restriction ("Team+").
    """
    tier = get_instance_entitlement(db)["tier"]
    try:
        return TIER_ORDER.index(tier) >= TIER_ORDER.index(min_tier)
    except ValueError:
        return False


def check_member_role_allowed(role: str, db: Session) -> None:
    """Raise 402 if `role` is one of the paid roles and the license is below
    Team. Base roles pass on every tier, including unlicensed."""
    if (role or "").lower() not in EXTENDED_MEMBER_ROLES:
        return
    if instance_tier_at_least("team", db):
        return
    raise HTTPException(
        402,
        f"The '{role}' role requires the Team plan or higher. "
        f"Base roles (owner, admin, editor, manager, team_lead, operator, "
        f"viewer, auditor) are available on every tier.",
    )
