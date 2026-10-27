"""
OIDC login orchestration: claim mapping, role resolution, account linking/
JIT-provisioning decisions. Kept separate from client.py (pure protocol
mechanics) and from routers/oidc_auth.py (HTTP layer) so the
account-takeover-sensitive decision logic here has a single, testable
home.
"""

from __future__ import annotations

import re

from sqlalchemy.orm import Session

from ... import models
from ...core.enums import MemberRole
from ...core.utils import new_id, ts_now


def resolve_claim(claim_mapping: dict, claims: dict, logical_key: str, fallback_claim: str) -> str:
    """logical_key is our name (e.g. "email"); claim_mapping may point it at
    a differently-named claim on this IdP. Falls back to fallback_claim
    (the OIDC-standard claim name) if unmapped."""
    claim_name = (claim_mapping or {}).get(logical_key) or fallback_claim
    value = claims.get(claim_name)
    return str(value) if value is not None else ""


def resolve_groups(claim_mapping: dict, claims: dict) -> list[str]:
    claim_name = (claim_mapping or {}).get("groups") or "groups"
    raw = claims.get(claim_name)
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, (list, tuple)):
        return [str(g) for g in raw]
    return []


def map_role(provider: models.OIDCProvider, claims: dict) -> str:
    """Resolve the org role a JIT-provisioned (or newly-linked) user gets.
    Only a role explicitly present in role_mapping for a group the token
    actually carries can grant anything above default_role — an IdP group
    claim the admin never configured a mapping for is silently ignored,
    never treated as "give them something reasonable." Both the mapped
    and the default role are validated against the real MemberRole
    vocabulary; an unrecognized value in either config field falls back to
    "viewer" rather than erroring the whole login (fail safe, not open)."""
    groups = resolve_groups(provider.claim_mapping, claims)
    role_mapping = provider.role_mapping or {}
    for group in groups:
        mapped = role_mapping.get(group)
        if mapped and MemberRole.coerce(mapped) is not None:
            return mapped
    default = provider.default_role or "viewer"
    if MemberRole.coerce(default) is None:
        return "viewer"
    return default


def find_existing_identity(
    db: Session, provider_id: str, subject: str
) -> models.OIDCIdentity | None:
    return (
        db.query(models.OIDCIdentity)
        .filter(
            models.OIDCIdentity.provider_id == provider_id, models.OIDCIdentity.subject == subject
        )
        .first()
    )


def find_user_by_email(db: Session, email: str) -> models.User | None:
    if not email:
        return None
    return db.query(models.User).filter(models.User.email == email, models.User.active).first()


def create_identity(
    db: Session, *, provider_id: str, subject: str, user_id: str, email: str
) -> models.OIDCIdentity:
    identity = models.OIDCIdentity(
        id=new_id("oidcid"),
        provider_id=provider_id,
        subject=subject,
        user_id=user_id,
        email_at_link_time=email,
        linked_at=ts_now(),
    )
    db.add(identity)
    return identity


_USERNAME_SANITIZE_RE = re.compile(r"[^a-z0-9._-]+")


def jit_provision_user(
    db: Session, *, provider: models.OIDCProvider, email: str, name: str, claims: dict
) -> models.User:
    """Create a brand-new platform account for a first-time OIDC login with
    no matching existing user — always global role "user" (never
    platform_admin; mirrors the same rule already applied to
    routers/organizations.py::create_org_user). If provider.org_id is set,
    also joins that org with a role from map_role(), never anything
    unmapped/elevated. A platform-wide provider (org_id is None) joins no
    org at all — a manager assigns one afterward."""
    # Prefer the IdP's own login/handle (OIDC standard claim
    # preferred_username — GitLab, Keycloak, Okta all send it) over the
    # email local-part: an email of admin@corp.example collides with
    # every other account whose email also starts with "admin@", forcing
    # an arbitrary admin2/admin3/... suffix even though the IdP already
    # has a perfectly good, usually-unique handle (e.g. "jsmith"). Falls
    # back to the email local-part when the claim is absent/unmapped, same
    # as before this was added.
    preferred_username = resolve_claim(
        provider.claim_mapping, claims, "preferred_username", "preferred_username"
    )
    raw_base = preferred_username.strip() or (email.split("@")[0] if email else "").strip()
    username_base = _USERNAME_SANITIZE_RE.sub("-", raw_base.lower()).strip("-") or f"oidc-{new_id('u')}"
    username = username_base
    suffix = 1
    while db.query(models.User).filter(models.User.username == username).first():
        suffix += 1
        username = f"{username_base}{suffix}"

    user = models.User(
        id=new_id("u"),
        username=username,
        email=email or None,
        display_name=(name or username).strip(),
        password_hash="",  # OIDC-only account — no platform password set
        role="user",
        created_at=ts_now(),
        active=True,
    )
    db.add(user)
    db.flush()

    if provider.org_id:
        role = map_role(provider, claims)
        db.add(
            models.OrganizationMember(
                id=new_id("om"),
                org_id=provider.org_id,
                user_id=user.id,
                role=role,
                created_at=ts_now(),
            )
        )
    return user
