from sqlalchemy import Boolean, Column, ForeignKey, String

from ..database import Base
from ._types import JSONB


class OIDCProvider(Base):
    """One OIDC/SSO configuration — either org-scoped or platform-wide.

    org_id set: the MSSP-SaaS case — one client organization's own IdP,
    configurable by that org's own admin (routers/oidc_admin.py), gated
    on the org's `sso` plan feature. JIT-provisioned users join this org
    with a role from role_mapping/default_role.

    org_id NULL: platform-wide SSO — the common single-company shape,
    where JIT-provisioned users get created with no organization
    membership at all; a manager assigns them to orgs/teams afterward.
    Configurable only by a platform_admin (routers/
    oidc_platform_admin.py) — role_mapping/default_role/enforced are
    meaningless here and not exposed by that router.

    client_secret is always stored via core/crypto.py's encrypt_str,
    never plaintext, regardless of scope."""

    __tablename__ = "oidc_providers"

    id = Column(String, primary_key=True)
    org_id = Column(
        String, ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True
    )
    name = Column(String, nullable=False)
    issuer_url = Column(String, nullable=False)
    client_id = Column(String, nullable=False)
    client_secret = Column(String, nullable=False)
    scopes = Column(JSONB, nullable=False, default=lambda: ["openid", "email", "profile"])

    # Populated from {issuer_url}/.well-known/openid-configuration by the
    # discovery step at create/refresh time — never hand-entered, so a
    # provider config can't silently point token exchange at one host and
    # JWKS validation at another.
    authorization_endpoint = Column(String, nullable=False, default="")
    token_endpoint = Column(String, nullable=False, default="")
    userinfo_endpoint = Column(String, nullable=False, default="")
    jwks_uri = Column(String, nullable=False, default="")

    # claim name -> platform attribute, e.g. {"email": "mail", "name":
    # "displayName", "groups": "roles"} for an IdP with nonstandard claims.
    claim_mapping = Column(
        JSONB,
        nullable=False,
        default=lambda: {"email": "email", "name": "name", "groups": "groups"},
    )
    # group/role claim VALUE -> platform MemberRole, e.g. {"platform-admins":
    # "admin", "analysts": "analyst"}. Unmatched/absent groups fall back to
    # default_role — never to an elevated role by omission.
    role_mapping = Column(JSONB, nullable=False, default=dict)
    default_role = Column(String, nullable=False, default="viewer")

    # Opt-out of core.ssrf_guard's private-address block for this
    # provider's issuer/discovery/JWKS calls — only for a self-hosted IdP
    # on an internal/split-horizon network. Settable only by a
    # platform_admin (enforced in routers/oidc_admin.py), not by the org
    # admin who otherwise owns this row: an org admin choosing where the
    # platform makes outbound requests to is exactly the SSRF trust
    # boundary this guard exists for in a multi-tenant deployment.
    allow_private_issuer = Column(Boolean, nullable=False, default=False)

    jit_provisioning_enabled = Column(Boolean, nullable=False, default=False)
    # Whether platform TOTP-MFA is still required after a successful OIDC
    # login for this org — independent of whatever MFA the IdP itself
    # enforces. Reuses the exact same mfa_pending mechanism as password
    # login (core/totp.py), not a parallel one.
    require_platform_mfa = Column(Boolean, nullable=False, default=False)

    # Optional — lets the login screen suggest this provider from an
    # email domain the user typed, before they've authenticated at all.
    email_domain = Column(String, nullable=False, default="")

    enabled = Column(Boolean, nullable=False, default=True)
    # "Obligatory OIDC" — password login is refused for this org's users
    # once true. Guarded at the API layer: can only be set after
    # last_test_login_at is non-null (a verified successful OIDC round
    # trip), so a broken config can't lock every org member out at once.
    enforced = Column(Boolean, nullable=False, default=False)
    last_test_login_at = Column(String, nullable=True)

    created_at = Column(String, nullable=False)
    updated_at = Column(String, nullable=False)
    created_by = Column(String, nullable=True)


class OIDCIdentity(Base):
    """Durable link between one IdP's `sub` claim and one platform user —
    created either by JIT provisioning or by an explicit, password-
    verified linking confirmation (never silently on email match alone;
    see routers/oidc_auth.py). Existence of this row is what lets
    subsequent logins skip the linking step entirely."""

    __tablename__ = "oidc_identities"

    id = Column(String, primary_key=True)
    provider_id = Column(
        String, ForeignKey("oidc_providers.id", ondelete="CASCADE"), nullable=False
    )
    subject = Column(String, nullable=False)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    email_at_link_time = Column(String, nullable=False, default="")
    linked_at = Column(String, nullable=False)


class OIDCAuthState(Base):
    """One row per in-flight authorization-code round trip — state is the
    CSRF token, code_verifier/nonce are the PKCE/replay defenses. Row is
    deleted on successful (or definitively failed) callback; anything
    left past its TTL is dead and rejected on lookup."""

    __tablename__ = "oidc_auth_states"

    state = Column(String, primary_key=True)
    provider_id = Column(
        String, ForeignKey("oidc_providers.id", ondelete="CASCADE"), nullable=False
    )
    code_verifier = Column(String, nullable=False)
    nonce = Column(String, nullable=False)
    redirect_after = Column(String, nullable=False, default="")
    created_at = Column(String, nullable=False)
    expires_at = Column(String, nullable=False)
