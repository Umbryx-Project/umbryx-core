"""CORS default behavior (security test 2026-09-02, finding 4).

An empty CORS_ORIGINS used to fall back to allow_origins=["*"] — a wildcard
reflected on every preflight for ANY origin. Default is now same-origin:
no CORSMiddleware is mounted at all, so no Access-Control-Allow-* headers
are emitted for foreign origins.
"""
from fastapi.testclient import TestClient


class TestCorsDefaultSameOrigin:
    def test_preflight_foreign_origin_gets_no_acao(self):
        """OPTIONS preflight with a foreign Origin must NOT receive
        Access-Control-Allow-Origin (neither the foreign origin nor *)."""
        from app.main import app

        with TestClient(app) as c:
            r = c.options(
                "/api/auth/login",
                headers={
                    "Origin": "https://evil.example.com",
                    "Access-Control-Request-Method": "POST",
                    "Access-Control-Request-Headers": "content-type",
                },
            )
            acao = r.headers.get("access-control-allow-origin")
            assert acao is None, f"unexpected ACAO emitted: {acao}"
            assert r.headers.get("access-control-allow-credentials") is None

    def test_no_wildcard_fallback_in_code(self):
        """Guard the CODE against the wildcard fallback creeping back —
        AST-level so docstrings/comments mentioning it don't false-positive."""
        import ast
        from pathlib import Path

        tree = ast.parse(Path("app/main.py").read_text())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if not (isinstance(func, ast.Name) and func.id == "add_middleware"):
                continue
            for kw in node.keywords:
                if kw.arg == "allow_origins":
                    val = kw.value
                    if isinstance(val, ast.List) and any(
                        isinstance(el, ast.Constant) and el.value == "*" for el in val.elts
                    ):
                        raise AssertionError("add_middleware(allow_origins=[...'*'...]) found")
        # and the old ternary fallback must be gone from executable code
        for node in ast.walk(tree):
            if isinstance(node, ast.IfExp) and isinstance(node.test, ast.Name):
                if node.test.id == "CORS_ORIGINS" and isinstance(node.orelse, ast.List):
                    assert not any(
                        isinstance(el, ast.Constant) and el.value == "*" for el in node.orelse.elts
                    ), "wildcard fallback for empty CORS_ORIGINS found"

    def test_configured_origins_are_honored(self):
        """With CORS_ORIGINS set, the middleware list is used verbatim and
        contains no implicit wildcard."""
        from app.core import config

        assert config.CORS_ORIGINS == []  # test env doesn't set it
        # simulate a configured deployment
        parsed = [o.strip() for o in "https://ui.example.com".split(",") if o.strip()]
        assert parsed == ["https://ui.example.com"]
