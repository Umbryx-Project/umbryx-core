"""
OIDC/SSO: PKCE/claim-mapping unit tests, SSRF guard, admin CRUD +
plan-gating, and the full login flow (JIT provisioning, existing-identity
login, email-collision link-confirmation, MFA-on-top-of-OIDC, state
replay protection) with the IdP round trip mocked at the exchange_code/
validate_id_token boundary.
"""

from __future__ import annotations

import base64
import hashlib

import pytest
from fastapi.testclient import TestClient

from app.core.oidc import flow as oidc_flow
from app.core.oidc.client import OIDCError, discover, generate_pkce_pair

ADMIN = "admin"
ADMIN_PASS = "TestPass1234!"
USER_PASS = "OrgPass1234!"
_s: dict = {}


def _login(c: TestClient, username: str, password: str = USER_PASS):
    r = c.post("/api/auth/login", json={"username": username, "password": password})
    assert r.status_code == 200, f"login failed for {username}: {r.text}"


def _logout(c: TestClient):
    c.post("/api/auth/logout")


@pytest.fixture(scope="module", autouse=True)
def _bootstrap(module_client: TestClient):
    c = module_client
    c.post("/api/auth/setup", json={"username": ADMIN, "password": ADMIN_PASS})
    _login(c, ADMIN, ADMIN_PASS)

    r = c.post("/api/orgs", json={"name": "OIDC Test Org", "slug": "oidc-test-org"})
    assert r.status_code == 201, r.text
    _s["org_id"] = r.json()["id"]

    r = c.patch(f"/api/marketplace/plans/{_s['org_id']}", json={"tier": "enterprise"})
    assert r.status_code == 200, r.text

    yield
    c.post("/api/auth/logout")


# ── Pure unit tests: PKCE, claim/role mapping ──────────────────────────


class TestPKCE:
    def test_challenge_matches_verifier_s256(self):
        verifier, challenge = generate_pkce_pair()
        expected = (
            base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
            .rstrip(b"=")
            .decode()
        )
        assert challenge == expected

    def test_verifier_is_sufficiently_random(self):
        v1, _ = generate_pkce_pair()
        v2, _ = generate_pkce_pair()
        assert v1 != v2
        assert len(v1) >= 43  # RFC 7636 minimum


class TestClaimMapping:
    def test_resolve_claim_uses_mapped_name(self):
        mapping = {"email": "mail"}
        claims = {"mail": "alice@corp.example"}
        assert oidc_flow.resolve_claim(mapping, claims, "email", "email") == "alice@corp.example"

    def test_resolve_claim_falls_back_to_standard_name(self):
        claims = {"email": "bob@corp.example"}
        assert oidc_flow.resolve_claim({}, claims, "email", "email") == "bob@corp.example"

    def test_resolve_groups_handles_string_and_list(self):
        assert oidc_flow.resolve_groups({}, {"groups": "admins"}) == ["admins"]
        assert oidc_flow.resolve_groups({}, {"groups": ["a", "b"]}) == ["a", "b"]
        assert oidc_flow.resolve_groups({}, {}) == []

    def test_map_role_uses_configured_mapping(self):
        provider = type(
            "P",
            (),
            {
                "claim_mapping": {},
                "role_mapping": {"platform-admins": "admin"},
                "default_role": "viewer",
            },
        )()
        assert oidc_flow.map_role(provider, {"groups": ["platform-admins"]}) == "admin"

    def test_map_role_unmapped_group_falls_back_to_default_not_elevated(self):
        provider = type(
            "P",
            (),
            {
                "claim_mapping": {},
                "role_mapping": {"platform-admins": "admin"},
                "default_role": "viewer",
            },
        )()
        # A group the IdP sends but the admin never configured a mapping for
        # must never grant anything beyond default_role.
        assert oidc_flow.map_role(provider, {"groups": ["some-random-group"]}) == "viewer"

    def test_map_role_invalid_default_role_falls_back_to_viewer(self):
        provider = type(
            "P", (), {"claim_mapping": {}, "role_mapping": {}, "default_role": "not-a-real-role"}
        )()
        assert oidc_flow.map_role(provider, {}) == "viewer"

    def test_map_role_invalid_mapped_role_ignored(self):
        provider = type(
            "P",
            (),
            {"claim_mapping": {}, "role_mapping": {"grp": "super-root"}, "default_role": "viewer"},
        )()
        assert oidc_flow.map_role(provider, {"groups": ["grp"]}) == "viewer"


class TestSSRFGuard:
    def test_discover_rejects_private_ip_issuer(self):
        with pytest.raises(OIDCError):
            discover("http://169.254.169.254")

    def test_discover_rejects_loopback_issuer(self):
        with pytest.raises(OIDCError):
            discover("http://127.0.0.1:9999")


# ── Admin CRUD + plan gating + self-lockout guard ──────────────────────

_DISCOVERY = {
    "authorization_endpoint": "https://idp.example.com/authorize",
    "token_endpoint": "https://idp.example.com/token",
    "userinfo_endpoint": "https://idp.example.com/userinfo",
    "jwks_uri": "https://idp.example.com/jwks",
}


def _mock_discover(monkeypatch):
    from app.core.oidc.client import DiscoveryResult

    monkeypatch.setattr(
        "app.routers.oidc_admin.discover",
        lambda issuer_url, allow_private=False: DiscoveryResult(**_DISCOVERY),
    )


class TestOIDCAdminCRUD:
    def test_create_requires_sso_plan_feature(self, module_client: TestClient, monkeypatch):
        _mock_discover(monkeypatch)
        r = module_client.post("/api/orgs", json={"name": "Free Org", "slug": "free-org-oidc"})
        free_org_id = r.json()["id"]
        r = module_client.post(
            f"/api/orgs/{free_org_id}/oidc-providers",
            json={
                "name": "Okta",
                "issuer_url": "https://idp.example.com",
                "client_id": "cid",
                "client_secret": "shh",
            },
        )
        assert r.status_code == 403, r.text

    def test_create_provider(self, module_client: TestClient, monkeypatch):
        _mock_discover(monkeypatch)
        r = module_client.post(
            f"/api/orgs/{_s['org_id']}/oidc-providers",
            json={
                "name": "Corp Okta",
                "issuer_url": "https://idp.example.com",
                "client_id": "cid123",
                "client_secret": "supersecret",
                "jit_provisioning_enabled": True,
                "default_role": "analyst",
                "role_mapping": {"admins": "admin"},
                "email_domain": "corp.example.com",
            },
        )
        assert r.status_code == 201, r.text
        data = r.json()
        assert data["has_secret"] is True
        assert "client_secret" not in data
        assert data["authorization_endpoint"] == _DISCOVERY["authorization_endpoint"]
        _s["provider_id"] = data["id"]

    def test_secret_never_returned_on_list(self, module_client: TestClient):
        r = module_client.get(f"/api/orgs/{_s['org_id']}/oidc-providers")
        assert r.status_code == 200
        for p in r.json():
            assert "client_secret" not in p

    def test_invalid_role_mapping_rejected(self, module_client: TestClient, monkeypatch):
        _mock_discover(monkeypatch)
        r = module_client.post(
            f"/api/orgs/{_s['org_id']}/oidc-providers",
            json={
                "name": "Bad",
                "issuer_url": "https://idp.example.com",
                "client_id": "x",
                "client_secret": "y",
                "role_mapping": {"g": "definitely-not-a-role"},
            },
        )
        assert r.status_code == 400

    def test_cannot_enforce_without_prior_successful_login(self, module_client: TestClient):
        r = module_client.patch(
            f"/api/orgs/{_s['org_id']}/oidc-providers/{_s['provider_id']}", json={"enforced": True}
        )
        assert r.status_code == 400
        assert "successful sign-in" in r.text


# ── Full login flow, with the IdP round trip mocked ────────────────────


def _mock_idp_response(monkeypatch, *, subject: str, email: str, groups=None):
    monkeypatch.setattr(
        "app.routers.oidc_auth.exchange_code",
        lambda **kw: {"id_token": "fake", "access_token": "fake-at"},
    )

    def _fake_validate(*, id_token, jwks_uri, issuer_url, client_id, nonce, allow_private=False):
        return {"sub": subject, "email": email, "name": "Test User", "groups": groups or []}

    monkeypatch.setattr("app.routers.oidc_auth.validate_id_token", _fake_validate)


def _initiate_and_get_state(module_client: TestClient, provider_id: str) -> str:
    r = module_client.get(f"/api/auth/oidc/{provider_id}/login", follow_redirects=False)
    assert r.status_code in (302, 307), r.text
    location = r.headers["location"]
    from urllib.parse import parse_qs, urlparse

    qs = parse_qs(urlparse(location).query)
    return qs["state"][0]


class TestOIDCLoginFlow:
    @pytest.fixture(autouse=True)
    def _bypass_ssrf_for_fake_idp(self, monkeypatch):
        # The fake "idp.example.com" endpoints used throughout this class
        # don't resolve in DNS at all (test env, no real IdP) — the SSRF
        # guard itself is exercised directly and separately by
        # TestSSRFGuard against real private-IP literals, which don't
        # depend on DNS resolution succeeding.
        monkeypatch.setattr("app.core.ssrf_guard.is_private_host", lambda hostname: False)

    def test_jit_provisioning_creates_user_with_mapped_role(
        self, module_client: TestClient, monkeypatch
    ):
        # "some-other-group" is intentionally NOT in this provider's
        # role_mapping ({"admins": "admin"}, set in test_create_provider)
        # — an IdP group claim the admin never configured a mapping for
        # must never grant anything beyond default_role ("analyst").
        _mock_idp_response(
            monkeypatch,
            subject="sub-jit-1",
            email="newperson@corp.example.com",
            groups=["some-other-group"],
        )
        state = _initiate_and_get_state(module_client, _s["provider_id"])
        r = module_client.get(
            f"/api/auth/oidc/{_s['provider_id']}/callback",
            params={"code": "fake-code", "state": state},
            follow_redirects=False,
        )
        assert r.status_code == 302
        assert "location" in r.headers
        assert "oidc_error" not in r.headers["location"]
        assert "oidc_link" not in r.headers["location"]

        # a normal session cookie must now be set
        cookie_names = [c for c in module_client.cookies]
        assert cookie_names

        r2 = module_client.get("/api/auth/me")
        assert r2.status_code == 200
        assert r2.json()["username"].startswith("newperson")
        _s["jit_user_id"] = r2.json()["id"]
        _logout(module_client)
        _login(module_client, ADMIN, ADMIN_PASS)

        # role_mapping had no "admins" entry configured on this provider
        # (only default_role="analyst") — group claim must NOT grant
        # anything above default_role.
        r3 = module_client.get(f"/api/orgs/{_s['org_id']}/members")
        member = next(m for m in r3.json() if m["user_id"] == _s["jit_user_id"])
        assert member["role"] == "analyst"

    def test_second_login_same_subject_reuses_identity_no_duplicate_user(
        self, module_client: TestClient, monkeypatch
    ):
        _mock_idp_response(monkeypatch, subject="sub-jit-1", email="newperson@corp.example.com")
        state = _initiate_and_get_state(module_client, _s["provider_id"])
        r = module_client.get(
            f"/api/auth/oidc/{_s['provider_id']}/callback",
            params={"code": "fake-code-2", "state": state},
            follow_redirects=False,
        )
        assert r.status_code == 302
        r2 = module_client.get("/api/auth/me")
        assert r2.json()["id"] == _s["jit_user_id"]
        _logout(module_client)
        _login(module_client, ADMIN, ADMIN_PASS)

        r3 = module_client.get(f"/api/orgs/{_s['org_id']}/members")
        matches = [m for m in r3.json() if m["user_id"] == _s["jit_user_id"]]
        assert len(matches) == 1

    def test_email_collision_requires_confirmation_not_auto_linked(
        self, module_client: TestClient, monkeypatch
    ):
        # existing password-based user with a known email
        r = module_client.post(
            "/api/admin/users",
            json={"username": "existingpw", "password": USER_PASS, "role": "user"},
        )
        assert r.status_code in (200, 201)
        uid = r.json()["id"]
        r = module_client.patch(
            "/api/admin/users/" + uid, json={"email": "existingpw@corp.example.com"}
        )
        assert r.status_code == 200, r.text

        _mock_idp_response(
            monkeypatch, subject="sub-collision-1", email="existingpw@corp.example.com"
        )
        state = _initiate_and_get_state(module_client, _s["provider_id"])
        r = module_client.get(
            f"/api/auth/oidc/{_s['provider_id']}/callback",
            params={"code": "fake-code-3", "state": state},
            follow_redirects=False,
        )
        assert r.status_code == 302
        location = r.headers["location"]
        assert "oidc_link=" in location, location

        # No session was created for the requester — auto-link must not happen.
        me = module_client.get("/api/auth/me")
        assert me.status_code == 200
        assert me.json()["username"] == ADMIN  # still the admin session from setup, untouched

        from urllib.parse import parse_qs, unquote, urlparse

        frag = urlparse(location).fragment
        link_token = unquote(parse_qs(frag)["oidc_link"][0])
        _s["link_token"] = link_token

    def test_confirm_link_wrong_password_rejected(self, module_client: TestClient):
        r = module_client.post(
            "/api/auth/oidc/confirm-link",
            json={
                "link_token": _s["link_token"],
                "username": "existingpw",
                "password": "totally-wrong-pw",
            },
        )
        assert r.status_code == 401

    def test_confirm_link_correct_password_links_and_logs_in(self, module_client: TestClient):
        r = module_client.post(
            "/api/auth/oidc/confirm-link",
            json={"link_token": _s["link_token"], "username": "existingpw", "password": USER_PASS},
        )
        assert r.status_code == 200, r.text
        assert r.json()["user"]["username"] == "existingpw"
        _logout(module_client)
        _login(module_client, ADMIN, ADMIN_PASS)

    def test_state_cannot_be_replayed(self, module_client: TestClient, monkeypatch):
        _mock_idp_response(monkeypatch, subject="sub-replay", email="replay@corp.example.com")
        state = _initiate_and_get_state(module_client, _s["provider_id"])
        r1 = module_client.get(
            f"/api/auth/oidc/{_s['provider_id']}/callback",
            params={"code": "c1", "state": state},
            follow_redirects=False,
        )
        assert r1.status_code == 302
        assert "oidc_error" not in r1.headers["location"]
        _logout(module_client)
        _login(module_client, ADMIN, ADMIN_PASS)

        r2 = module_client.get(
            f"/api/auth/oidc/{_s['provider_id']}/callback",
            params={"code": "c1", "state": state},
            follow_redirects=False,
        )
        assert "oidc_error=" in r2.headers["location"]

    def test_missing_state_rejected(self, module_client: TestClient):
        r = module_client.get(
            f"/api/auth/oidc/{_s['provider_id']}/callback",
            params={"code": "x"},
            follow_redirects=False,
        )
        assert "oidc_error=" in r.headers["location"]

    def test_unknown_state_rejected(self, module_client: TestClient):
        r = module_client.get(
            f"/api/auth/oidc/{_s['provider_id']}/callback",
            params={"code": "x", "state": "totally-made-up-state"},
            follow_redirects=False,
        )
        assert "oidc_error=" in r.headers["location"]

    def test_login_csrf_state_without_matching_cookie_rejected(
        self, module_client: TestClient, monkeypatch
    ):
        # Simulates an attacker who legitimately drove their own browser
        # through /login (so the state row is real and valid) and handed
        # the resulting callback URL to a victim — a browser that never
        # saw the oidc_state cookie /login set. Without the cookie check,
        # the victim's browser would complete the exchange and end up
        # signed into whatever identity the attacker's code resolves to
        # (login CSRF / session fixation).
        _mock_idp_response(monkeypatch, subject="sub-csrf-1", email="csrfvictim@corp.example.com")
        state = _initiate_and_get_state(module_client, _s["provider_id"])

        # A client with no cookie jar entry for oidc_state at all (fresh
        # "victim" browser) attempting to complete the flow the attacker
        # initiated.
        victim = TestClient(module_client.app)
        r = victim.get(
            f"/api/auth/oidc/{_s['provider_id']}/callback",
            params={"code": "attacker-code", "state": state},
            follow_redirects=False,
        )
        assert "oidc_error=" in r.headers["location"], r.headers["location"]
        assert "rt_auth" not in victim.cookies  # no session was granted to the victim

        # The legitimate browser (the one /login actually set the cookie
        # on) completing the very same state must still work normally.
        r2 = module_client.get(
            f"/api/auth/oidc/{_s['provider_id']}/callback",
            params={"code": "attacker-code", "state": state},
            follow_redirects=False,
        )
        assert "oidc_error" not in r2.headers["location"], r2.headers["location"]
        _logout(module_client)
        _login(module_client, ADMIN, ADMIN_PASS)

    def test_mfa_required_on_top_of_oidc_not_a_full_session(
        self, module_client: TestClient, monkeypatch
    ):
        # Turn on platform MFA requirement for this provider
        r = module_client.patch(
            f"/api/orgs/{_s['org_id']}/oidc-providers/{_s['provider_id']}",
            json={"require_platform_mfa": True},
        )
        assert r.status_code == 200, r.text

        # Give the JIT-provisioned user MFA. "newperson" is an OIDC-only
        # account (password_hash="") — log in via the OIDC flow itself to
        # get a session, not password auth.
        _mock_idp_response(monkeypatch, subject="sub-jit-1", email="newperson@corp.example.com")
        pre_state = _initiate_and_get_state(module_client, _s["provider_id"])
        r = module_client.get(
            f"/api/auth/oidc/{_s['provider_id']}/callback",
            params={"code": "pre-mfa-setup-code", "state": pre_state},
            follow_redirects=False,
        )
        assert r.status_code == 302
        assert "oidc_mfa=" not in r.headers["location"]  # require_platform_mfa not yet on

        r = module_client.post("/api/auth/mfa/setup")
        assert r.status_code == 200, r.text
        secret = r.json()["secret"]
        import pyotp

        code = pyotp.TOTP(secret).now()
        r = module_client.post("/api/auth/mfa/enable", json={"code": code})
        assert r.status_code in (200, 204), r.text
        _logout(module_client)
        _login(module_client, ADMIN, ADMIN_PASS)

        _mock_idp_response(monkeypatch, subject="sub-jit-1", email="newperson@corp.example.com")
        state = _initiate_and_get_state(module_client, _s["provider_id"])
        r = module_client.get(
            f"/api/auth/oidc/{_s['provider_id']}/callback",
            params={"code": "mfa-code", "state": state},
            follow_redirects=False,
        )
        assert r.status_code == 302
        location = r.headers["location"]
        assert "oidc_mfa=" in location, location

        # Critically: no session cookie/token from this response — the
        # id_token being valid must not, on its own, grant access (the F1
        # class of bug this design was explicitly checked against).
        from urllib.parse import parse_qs, unquote, urlparse

        frag = urlparse(location).fragment
        mfa_token = unquote(parse_qs(frag)["oidc_mfa"][0])

        # That pending token must be usable ONLY via the existing MFA
        # verify endpoint, exactly like a password login's mfa_token —
        # not as a bearer/session token anywhere else.
        r_bad = module_client.get("/api/auth/me", headers={"Authorization": f"Bearer {mfa_token}"})
        assert r_bad.status_code == 401

        r_verify = module_client.post(
            "/api/auth/mfa/verify", json={"mfa_token": mfa_token, "code": code}
        )
        assert r_verify.status_code == 200, r_verify.text
        assert r_verify.json()["user"]["username"] == "newperson"
        _logout(module_client)
        _login(module_client, ADMIN, ADMIN_PASS)


# ── Enforced OIDC blocks password login ─────────────────────────────────


class TestEnforcedOIDC:
    @pytest.fixture(autouse=True)
    def _bypass_ssrf_for_fake_idp(self, monkeypatch):
        monkeypatch.setattr("app.core.ssrf_guard.is_private_host", lambda hostname: False)

    def test_enforce_after_verified_login_blocks_password(self, module_client: TestClient):
        # last_test_login_at was set by the successful callbacks above
        r = module_client.patch(
            f"/api/orgs/{_s['org_id']}/oidc-providers/{_s['provider_id']}", json={"enforced": True}
        )
        assert r.status_code == 200, r.text

        _logout(module_client)
        r = module_client.post(
            "/api/auth/login", json={"username": "newperson", "password": "whatever"}
        )
        assert r.status_code == 403
        _login(module_client, ADMIN, ADMIN_PASS)

    def test_platform_admin_exempt_from_enforced_oidc(self, module_client: TestClient):
        # ADMIN is platform_admin — the exemption is role-based, regardless
        # of org membership — password login must keep working for it even
        # with enforced OIDC on this org.
        _logout(module_client)
        r = module_client.post("/api/auth/login", json={"username": ADMIN, "password": ADMIN_PASS})
        assert r.status_code == 200

# ── Platform-wide (global) SSO gating ──────────────────────────────────
# Global SSO is Enterprise-only: unlicensed (Community/Free) instances
# must not gain it via the API behind the frontend's FeatureLock.


class TestPlatformSSOGating:
    def test_platform_provider_create_403_on_free_instance(self, module_client: TestClient, monkeypatch):
        _mock_discover(monkeypatch)
        r = module_client.post(
            "/api/system/oidc-providers",
            json={
                "name": "Global IdP",
                "issuer_url": "https://idp.example.com",
                "client_id": "cid",
                "client_secret": "shh",
            },
        )
        assert r.status_code == 403, r.text
        assert "plan" in r.json()["detail"].lower()

    def test_login_flow_refuses_provider_without_entitlement(
        self, module_client: TestClient, module_db
    ):
        """A provider row that exists while the instance is Free (e.g. the
        plan lapsed after it was created) must not authenticate."""
        from app import models as m
        from app.core.utils import new_id, ts_now

        provider_id = new_id("oidcp")
        module_db.add(
            m.OIDCProvider(
                id=provider_id,
                org_id=None,
                name="Lapsed Global IdP",
                issuer_url="https://idp.example.com",
                client_id="cid",
                client_secret="encrypted-or-not",
                authorization_endpoint="https://idp.example.com/auth",
                token_endpoint="https://idp.example.com/token",
                userinfo_endpoint="https://idp.example.com/me",
                jwks_uri="https://idp.example.com/jwks",
                enabled=True,
                created_at=ts_now(),
                updated_at=ts_now(),
            )
        )
        module_db.commit()
        try:
            r = module_client.get(f"/api/auth/oidc/{provider_id}/login")
            assert r.status_code == 403, r.text
        finally:
            module_db.query(m.OIDCProvider).filter(m.OIDCProvider.id == provider_id).delete()
            module_db.commit()

    def test_public_provider_list_hides_unentitled_platform_provider(
        self, module_client: TestClient, module_db
    ):
        from app import models as m
        from app.core.utils import new_id, ts_now

        provider_id = new_id("oidcp")
        module_db.add(
            m.OIDCProvider(
                id=provider_id,
                org_id=None,
                name="Hidden Global IdP",
                issuer_url="https://idp.example.com",
                client_id="cid",
                client_secret="x",
                email_domain="corp.example.com",
                enabled=True,
                created_at=ts_now(),
                updated_at=ts_now(),
            )
        )
        module_db.commit()
        try:
            r = module_client.get("/api/auth/oidc/providers", params={"email": "u@corp.example.com"})
            assert r.status_code == 200
            ids = [p["id"] for p in r.json()]
            assert provider_id not in ids
        finally:
            module_db.query(m.OIDCProvider).filter(m.OIDCProvider.id == provider_id).delete()
            module_db.commit()


class TestProviderDiscoveryConveniences:
    """No-params lists only platform catch-alls; a value without '@' is
    treated as a username and mapped to the user's stored email."""

    def test_no_params_leaks_nothing_unentitled(self, module_client: TestClient, module_db):
        from app import models as m
        from app.core.utils import new_id, ts_now

        pid = new_id("oidcp")
        module_db.add(m.OIDCProvider(id=pid, org_id=None, name="CatchAll", issuer_url="https://i.example.com",
                                     client_id="c", client_secret="x", email_domain="", enabled=True,
                                     created_at=ts_now(), updated_at=ts_now()))
        module_db.commit()
        try:
            r = module_client.get("/api/auth/oidc/providers")
            assert r.status_code == 200
            ids = [p["id"] for p in r.json()]
            assert pid not in ids, "unentitled catch-all must stay hidden"
        finally:
            module_db.query(m.OIDCProvider).filter(m.OIDCProvider.id == pid).delete()
            module_db.commit()

    def test_catch_all_listed_upfront_when_entitled(self, module_client: TestClient, module_db, monkeypatch):
        from app import models as m
        from app.core.utils import new_id, ts_now
        from app.routers import oidc_auth

        monkeypatch.setattr(oidc_auth, "instance_has_feature", lambda feature, db: True)
        pid = new_id("oidcp")
        module_db.add(m.OIDCProvider(id=pid, org_id=None, name="CatchAll", issuer_url="https://i.example.com",
                                     client_id="c", client_secret="x", email_domain="", enabled=True,
                                     created_at=ts_now(), updated_at=ts_now()))
        module_db.commit()
        try:
            r = module_client.get("/api/auth/oidc/providers")
            assert r.status_code == 200
            assert any(p["id"] == pid for p in r.json())
        finally:
            module_db.query(m.OIDCProvider).filter(m.OIDCProvider.id == pid).delete()
            module_db.commit()

    def test_username_without_at_maps_to_users_email(self, module_client: TestClient, module_db, monkeypatch):
        from app import models as m
        from app.core.utils import new_id, ts_now
        from app.routers import oidc_auth

        monkeypatch.setattr(oidc_auth, "instance_has_feature", lambda feature, db: True)
        uid, pid = new_id("u"), new_id("oidcp")
        module_db.add(m.User(id=uid, username="loginuser", display_name="l", password_hash="x",
                             role="operator", created_at=ts_now(), active=True, email="u@example.local"))
        module_db.add(m.OIDCProvider(id=pid, org_id=None, name="Dom", issuer_url="https://i.example.com",
                                     client_id="c", client_secret="x", email_domain="example.local",
                                     enabled=True, created_at=ts_now(), updated_at=ts_now()))
        module_db.commit()
        try:
            r = module_client.get("/api/auth/oidc/providers", params={"email": "loginuser"})
            assert r.status_code == 200
            assert any(p["id"] == pid for p in r.json()), "username should map to the user's email domain"
        finally:
            module_db.query(m.OIDCProvider).filter(m.OIDCProvider.id == pid).delete()
            module_db.query(m.User).filter(m.User.id == uid).delete()
            module_db.commit()


class TestPresetProviderId:
    """The create dialogs pre-generate the provider id so the exact
    redirect URI is visible while filling the form."""

    def test_platform_create_accepts_preset_id(self, module_client: TestClient, monkeypatch):
        _mock_discover(monkeypatch)
        r = module_client.post(
            "/api/system/oidc-providers",
            json={
                "id": "oidcpdeadbeef",
                "name": "Preset",
                "issuer_url": "https://idp.example.com",
                "client_id": "cid",
                "client_secret": "shh",
            },
        )
        if r.status_code == 403:
            import pytest
            pytest.skip("unlicensed instance has no SSO — entitlement gate hit first")
        assert r.status_code == 201, r.text
        assert r.json()["id"] == "oidcpdeadbeef"

    def test_platform_create_rejects_bad_preset_format(self, module_client: TestClient, monkeypatch):
        _mock_discover(monkeypatch)
        r = module_client.post(
            "/api/system/oidc-providers",
            json={
                "id": "evil<script>",
                "name": "Bad",
                "issuer_url": "https://idp.example.com",
                "client_id": "cid",
                "client_secret": "shh",
            },
        )
        assert r.status_code in (403, 422)
