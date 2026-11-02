"""
Platform-admin CRUD for platform-wide OIDC/SSO providers (org_id NULL —
see models/oidc.py::OIDCProvider's docstring). The org-scoped MSSP case
lives in routers/oidc_admin.py, unchanged; this is the parallel path for
the common single-company shape, where SSO should just work for the
whole platform and managers sort people into orgs/teams afterward.

Deliberately narrower than the org-scoped schema: no default_role/
role_mapping (JIT-provisioned users join no org, so there's no org role
to assign) and no `enforced` (obligatory SSO / disable-passwords) — its
blast radius for "every user on the platform" needs its own design, not
a reuse of the per-org toggle. allow_private_issuer is available here
too, same SSRF-guard opt-out as the org-scoped router, and needs no
extra gate since this whole router is already platform_admin-only.
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
from ..core.deps import require_admin
from ..core.oidc.client import OIDCError, discover
from ..core.plan import PlanFeature, instance_has_feature
from ..core.utils import new_id, ts_now
from ..database import get_db

router = APIRouter(prefix="/api/system/oidc-providers", tags=["oidc-platform-admin"])


def _require_sso(db: Session) -> None:
    """Global SSO is an Enterprise-tier feature. Unlicensed (Community)
    instances resolve to Free and must not gain platform-wide providers by
    talking to the API behind the frontend's FeatureLock — the same gate
    the org-scoped router applies, checked against the instance
    entitlement instead of a single org's plan."""
    if not instance_has_feature(PlanFeature.SSO, db):
        raise HTTPException(
            403, "SSO/OIDC requires a higher plan tier. Contact your administrator."
        )


class PlatformOIDCProviderOut(BaseModel):
    id: str
    name: str
    issuer_url: str
    client_id: str
    scopes: list[str]
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str
    claim_mapping: dict
    jit_provisioning_enabled: bool
    require_platform_mfa: bool
    email_domain: str
    allow_private_issuer: bool
    enabled: bool
    last_test_login_at: str | None
    created_at: str
    updated_at: str
    has_secret: bool

    model_config = {"from_attributes": True}


def _out(p: models.OIDCProvider) -> PlatformOIDCProviderOut:
    return PlatformOIDCProviderOut(
        id=p.id,
        name=p.name,
        issuer_url=p.issuer_url,
        client_id=p.client_id,
        scopes=p.scopes or [],
        authorization_endpoint=p.authorization_endpoint,
        token_endpoint=p.token_endpoint,
        userinfo_endpoint=p.userinfo_endpoint,
        jwks_uri=p.jwks_uri,
        claim_mapping=p.claim_mapping or {},
        jit_provisioning_enabled=p.jit_provisioning_enabled,
        require_platform_mfa=p.require_platform_mfa,
        email_domain=p.email_domain,
        allow_private_issuer=p.allow_private_issuer,
        enabled=p.enabled,
        last_test_login_at=p.last_test_login_at,
        created_at=p.created_at,
        updated_at=p.updated_at,
        has_secret=bool(p.client_secret),
    )


class PlatformOIDCProviderCreate(BaseModel):
    # Optional client-generated id — lets the create dialog show the exact
    # redirect URI before the provider exists. Validated (format + unique).
    id: str | None = Field(default=None, pattern=r"^oidcp[0-9a-f]{8}$")
    name: str = Field(..., min_length=1, max_length=100)
    issuer_url: str
    client_id: str
    client_secret: str
    scopes: list[str] = Field(default_factory=lambda: ["openid", "email", "profile"])
    claim_mapping: dict = Field(
        default_factory=lambda: {"email": "email", "name": "name", "groups": "groups"}
    )
    jit_provisioning_enabled: bool = False
    require_platform_mfa: bool = False
    email_domain: str = ""
    allow_private_issuer: bool = False


class PlatformOIDCProviderUpdate(BaseModel):
    name: str | None = None
    issuer_url: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    scopes: list[str] | None = None
    claim_mapping: dict | None = None
    jit_provisioning_enabled: bool | None = None
    require_platform_mfa: bool | None = None
    email_domain: str | None = None
    allow_private_issuer: bool | None = None
    enabled: bool | None = None


@router.get("", response_model=list[PlatformOIDCProviderOut])
def list_platform_oidc_providers(
    db: Annotated[Session, Depends(get_db)],
    _admin: Annotated[models.User, Depends(require_admin)],
):
    rows = db.query(models.OIDCProvider).filter(models.OIDCProvider.org_id.is_(None)).all()
    return [_out(p) for p in rows]


@router.post("", status_code=201, response_model=PlatformOIDCProviderOut)
def create_platform_oidc_provider(
    body: PlatformOIDCProviderCreate,
    db: Annotated[Session, Depends(get_db)],
    admin: Annotated[models.User, Depends(require_admin)],
):
    _require_sso(db)
    try:
        disco = discover(body.issuer_url, allow_private=body.allow_private_issuer)
    except OIDCError as exc:
        raise HTTPException(400, f"OIDC discovery failed: {exc}") from exc

    if body.id and db.query(models.OIDCProvider).filter(models.OIDCProvider.id == body.id).first():
        raise HTTPException(409, "Provider id already taken — regenerate and retry")
    provider = models.OIDCProvider(
        id=body.id or new_id("oidcp"),
        org_id=None,
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
        role_mapping={},
        default_role="viewer",  # unused — no org join happens for a platform-wide provider
        jit_provisioning_enabled=body.jit_provisioning_enabled,
        require_platform_mfa=body.require_platform_mfa,
        email_domain=body.email_domain.strip().lower(),
        allow_private_issuer=body.allow_private_issuer,
        enabled=True,
        enforced=False,
        created_at=ts_now(),
        updated_at=ts_now(),
        created_by=admin.id,
    )
    db.add(provider)
    log_action(
        db,
        action=ACT_OIDC_PROVIDER_CREATE,
        actor_id=admin.id,
        actor_name=admin.username,
        target_type="oidc_provider",
        target_id=provider.id,
        detail={"org_id": None, "scope": "platform", "issuer_url": provider.issuer_url},
    )
    db.commit()
    db.refresh(provider)
    return _out(provider)


@router.patch("/{provider_id}", response_model=PlatformOIDCProviderOut)
def update_platform_oidc_provider(
    provider_id: str,
    body: PlatformOIDCProviderUpdate,
    db: Annotated[Session, Depends(get_db)],
    admin: Annotated[models.User, Depends(require_admin)],
):
    _require_sso(db)
    provider = (
        db.query(models.OIDCProvider)
        .filter(models.OIDCProvider.id == provider_id, models.OIDCProvider.org_id.is_(None))
        .first()
    )
    if not provider:
        raise HTTPException(404, "Platform OIDC provider not found")

    data = body.model_dump(exclude_unset=True)

    needs_rediscovery = (
        "issuer_url" in data and data["issuer_url"].rstrip("/") != provider.issuer_url
    )
    if needs_rediscovery:
        effective_allow_private = data.get("allow_private_issuer", provider.allow_private_issuer)
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
        actor_id=admin.id,
        actor_name=admin.username,
        target_type="oidc_provider",
        target_id=provider.id,
        detail={"org_id": None, "scope": "platform", "fields": sorted(data.keys())},
    )
    db.commit()
    db.refresh(provider)
    return _out(provider)


@router.delete("/{provider_id}", status_code=204)
def delete_platform_oidc_provider(
    provider_id: str,
    db: Annotated[Session, Depends(get_db)],
    admin: Annotated[models.User, Depends(require_admin)],
):
    _require_sso(db)
    provider = (
        db.query(models.OIDCProvider)
        .filter(models.OIDCProvider.id == provider_id, models.OIDCProvider.org_id.is_(None))
        .first()
    )
    if not provider:
        raise HTTPException(404, "Platform OIDC provider not found")
    db.delete(provider)
    log_action(
        db,
        action=ACT_OIDC_PROVIDER_DELETE,
        actor_id=admin.id,
        actor_name=admin.username,
        target_type="oidc_provider",
        target_id=provider_id,
        detail={"org_id": None, "scope": "platform"},
    )
    db.commit()
