"""
Org-admin CRUD for OIDC/SSO providers. Public login-flow endpoints live in
routers/oidc_auth.py.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import models
from ..core.audit import (
    ACT_OIDC_PROVIDER_CREATE,
    ACT_OIDC_PROVIDER_DELETE,
    ACT_OIDC_PROVIDER_UPDATE,
    log_action,
)
from ..core.crypto import encrypt_str
from ..core.deps import get_current_user, is_platform_admin
from ..core.enums import MemberRole
from ..core.oidc.client import OIDCError, discover
from ..core.org_access import require_org_admin
from ..core.plan import PlanFeature, has_feature
from ..core.utils import new_id, ts_now
from ..database import get_db

router = APIRouter(prefix="/api/orgs/{org_id}/oidc-providers", tags=["oidc-admin"])


class OIDCProviderOut(BaseModel):
    id: str
    org_id: str
    name: str
    issuer_url: str
    client_id: str
    scopes: list[str]
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str
    claim_mapping: dict
    role_mapping: dict
    default_role: str
    jit_provisioning_enabled: bool
    require_platform_mfa: bool
    email_domain: str
    allow_private_issuer: bool
    enabled: bool
    enforced: bool
    last_test_login_at: str | None
    created_at: str
    updated_at: str
    # Never client_secret — not even the encrypted form. has_secret lets
    # the UI show "configured" without ever round-tripping the value.
    has_secret: bool

    model_config = {"from_attributes": True}


def _out(p: models.OIDCProvider) -> OIDCProviderOut:
    return OIDCProviderOut(
        id=p.id,
        org_id=p.org_id,
        name=p.name,
        issuer_url=p.issuer_url,
        client_id=p.client_id,
        scopes=p.scopes or [],
        authorization_endpoint=p.authorization_endpoint,
        token_endpoint=p.token_endpoint,
        userinfo_endpoint=p.userinfo_endpoint,
        jwks_uri=p.jwks_uri,
        claim_mapping=p.claim_mapping or {},
        role_mapping=p.role_mapping or {},
        default_role=p.default_role,
        jit_provisioning_enabled=p.jit_provisioning_enabled,
        require_platform_mfa=p.require_platform_mfa,
        email_domain=p.email_domain,
        allow_private_issuer=p.allow_private_issuer,
        enabled=p.enabled,
        enforced=p.enforced,
        last_test_login_at=p.last_test_login_at,
        created_at=p.created_at,
        updated_at=p.updated_at,
        has_secret=bool(p.client_secret),
    )


class OIDCProviderCreate(BaseModel):
    # Optional client-generated id (format ^oidcp[0-9a-f]{8}$): lets the
    # create dialog show the exact redirect URI BEFORE the provider exists
    # (the admin registers it in the IdP while filling the form). The
    # handler validates format + uniqueness; opaque otherwise.
    id: str | None = Field(default=None, pattern=r"^oidcp[0-9a-f]{8}$")
    name: str = Field(..., min_length=1, max_length=100)
    issuer_url: str
    client_id: str
    client_secret: str
    scopes: list[str] = Field(default_factory=lambda: ["openid", "email", "profile"])
    claim_mapping: dict = Field(
        default_factory=lambda: {"email": "email", "name": "name", "groups": "groups"}
    )
    role_mapping: dict = Field(default_factory=dict)
    default_role: str = "viewer"
    jit_provisioning_enabled: bool = False
    require_platform_mfa: bool = False
    email_domain: str = ""
    # platform_admin-only — see OIDCProvider.allow_private_issuer's
    # docstring. Accepted here (rather than a separate endpoint) so the
    # create/update payload shape stays uniform; enforcement is in the
    # handler, not the schema.
    allow_private_issuer: bool = False


class OIDCProviderUpdate(BaseModel):
    name: str | None = None
    issuer_url: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    scopes: list[str] | None = None
    claim_mapping: dict | None = None
    role_mapping: dict | None = None
    default_role: str | None = None
    jit_provisioning_enabled: bool | None = None
    require_platform_mfa: bool | None = None
    email_domain: str | None = None
    allow_private_issuer: bool | None = None
    enabled: bool | None = None
    enforced: bool | None = None


def _validate_role_fields(default_role: str, role_mapping: dict) -> None:
    if MemberRole.coerce(default_role) is None:
        raise HTTPException(400, f"Invalid default_role. Valid: {sorted(MemberRole.values())}")
    for group, role in (role_mapping or {}).items():
        if MemberRole.coerce(role) is None:
            raise HTTPException(400, f"Invalid role {role!r} mapped for group {group!r}")


@router.get("", response_model=list[OIDCProviderOut])
def list_oidc_providers(
    org_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    require_org_admin(db, org_id, user)
    rows = db.query(models.OIDCProvider).filter(models.OIDCProvider.org_id == org_id).all()
    return [_out(p) for p in rows]


@router.post("", status_code=201, response_model=OIDCProviderOut)
def create_oidc_provider(
    org_id: str,
    body: OIDCProviderCreate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    require_org_admin(db, org_id, user)
    if not has_feature(org_id, PlanFeature.SSO, db):
        raise HTTPException(
            403, "SSO/OIDC requires a higher plan tier. Contact your administrator."
        )
    if body.allow_private_issuer and not is_platform_admin(user):
        raise HTTPException(
            403,
            "allow_private_issuer can only be set by a platform admin — it opts this "
            "provider's outbound requests out of the SSRF guard.",
        )
    _validate_role_fields(body.default_role, body.role_mapping)

    try:
        disco = discover(body.issuer_url, allow_private=body.allow_private_issuer)
    except OIDCError as exc:
        raise HTTPException(400, f"OIDC discovery failed: {exc}") from exc

    if body.id and db.query(models.OIDCProvider).filter(models.OIDCProvider.id == body.id).first():
        raise HTTPException(409, "Provider id already taken — regenerate and retry")
    provider = models.OIDCProvider(
        id=body.id or new_id("oidcp"),
        org_id=org_id,
        name=body.name.strip(),
        issuer_url=body.issuer_url.rstrip("/"),
        client_id=body.client_id.strip(),
        client_secret=encrypt_str(body.client_secret),
        scopes=body.scopes,
        authorization_endpoint=disco.authorization_endpoint,
        token_endpoint=disco.token_endpoint,
        userinfo_endpoint=disco.userinfo_endpoint,
        jwks_uri=disco.jwks_uri,
        claim_mapping=body.claim_mapping,
        role_mapping=body.role_mapping,
        default_role=body.default_role,
        jit_provisioning_enabled=body.jit_provisioning_enabled,
        require_platform_mfa=body.require_platform_mfa,
        email_domain=body.email_domain.strip().lower(),
        allow_private_issuer=body.allow_private_issuer,
        enabled=True,
        enforced=False,
        created_at=ts_now(),
        updated_at=ts_now(),
        created_by=user.id,
    )
    db.add(provider)
    log_action(
        db,
        action=ACT_OIDC_PROVIDER_CREATE,
        actor_id=user.id,
        actor_name=user.username,
        target_type="oidc_provider",
        target_id=provider.id,
        detail={"org_id": org_id, "issuer_url": provider.issuer_url},
    )
    db.commit()
    db.refresh(provider)
    return _out(provider)


@router.patch("/{provider_id}", response_model=OIDCProviderOut)
def update_oidc_provider(
    org_id: str,
    provider_id: str,
    body: OIDCProviderUpdate,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    require_org_admin(db, org_id, user)
    provider = (
        db.query(models.OIDCProvider)
        .filter(models.OIDCProvider.id == provider_id, models.OIDCProvider.org_id == org_id)
        .first()
    )
    if not provider:
        raise HTTPException(404, "OIDC provider not found")

    if body.allow_private_issuer is not None and not is_platform_admin(user):
        raise HTTPException(
            403,
            "allow_private_issuer can only be changed by a platform admin — it opts "
            "this provider's outbound requests out of the SSRF guard.",
        )

    if body.enforced and not provider.enforced:
        # The self-lockout guard from spec §5: obligatory OIDC can only be
        # switched on after at least one real, complete login round trip
        # already succeeded through this exact provider config — set by
        # routers/oidc_auth.py::_finish_login on every successful callback,
        # never by this endpoint itself (an admin can't just claim it works).
        if not provider.last_test_login_at:
            raise HTTPException(
                400,
                "Complete at least one successful sign-in through this provider "
                "before making it mandatory — otherwise a misconfiguration "
                "would lock out every user in the organization at once.",
            )

    data = body.model_dump(exclude_unset=True)
    new_default_role = data.get("default_role", provider.default_role)
    new_role_mapping = data.get("role_mapping", provider.role_mapping)
    if "default_role" in data or "role_mapping" in data:
        _validate_role_fields(new_default_role, new_role_mapping)

    needs_rediscovery = (
        "issuer_url" in data and data["issuer_url"].rstrip("/") != provider.issuer_url
    )
    if needs_rediscovery:
        effective_allow_private = data.get("allow_private_issuer", provider.allow_private_issuer)
        # An org admin retargeting issuer_url on a provider that already
        # has allow_private_issuer=True (granted earlier, for a specific
        # trusted internal IdP) would otherwise inherit that grant for an
        # ARBITRARY new private-network URL — e.g. the cloud metadata
        # endpoint, or another tenant's internal service — with no fresh
        # platform_admin approval of the new target. The field-level check
        # above only covers explicitly setting allow_private_issuer in
        # *this* request; re-require the same gate here whenever the
        # effective value (old or new) is True, since changing the target
        # URL is exactly the action the guard exists to control.
        if effective_allow_private and not is_platform_admin(user):
            raise HTTPException(
                403,
                "Changing issuer_url on a provider with allow_private_issuer set requires "
                "a platform admin — it re-targets an SSRF-guard-exempt outbound request.",
            )
        try:
            disco = discover(data["issuer_url"], allow_private=effective_allow_private)
        except OIDCError as exc:
            raise HTTPException(400, f"OIDC discovery failed: {exc}") from exc
        provider.authorization_endpoint = disco.authorization_endpoint
        provider.token_endpoint = disco.token_endpoint
        provider.userinfo_endpoint = disco.userinfo_endpoint
        provider.jwks_uri = disco.jwks_uri
        provider.issuer_url = data["issuer_url"].rstrip("/")
        data.pop("issuer_url")

    if data.get("client_secret"):
        provider.client_secret = encrypt_str(data.pop("client_secret"))
    else:
        data.pop("client_secret", None)
    if "email_domain" in data:
        data["email_domain"] = data["email_domain"].strip().lower()

    for key, value in data.items():
        setattr(provider, key, value)
    provider.updated_at = ts_now()

    log_action(
        db,
        action=ACT_OIDC_PROVIDER_UPDATE,
        actor_id=user.id,
        actor_name=user.username,
        target_type="oidc_provider",
        target_id=provider.id,
        detail={"org_id": org_id, "fields": sorted(data.keys())},
    )
    db.commit()
    db.refresh(provider)
    return _out(provider)


@router.delete("/{provider_id}", status_code=204)
def delete_oidc_provider(
    org_id: str,
    provider_id: str,
    db: Annotated[Session, Depends(get_db)],
    user: Annotated[models.User, Depends(get_current_user)],
):
    require_org_admin(db, org_id, user)
    provider = (
        db.query(models.OIDCProvider)
        .filter(models.OIDCProvider.id == provider_id, models.OIDCProvider.org_id == org_id)
        .first()
    )
    if not provider:
        raise HTTPException(404, "OIDC provider not found")
    db.delete(provider)
    log_action(
        db,
        action=ACT_OIDC_PROVIDER_DELETE,
        actor_id=user.id,
        actor_name=user.username,
        target_type="oidc_provider",
        target_id=provider_id,
        detail={"org_id": org_id},
    )
    db.commit()
