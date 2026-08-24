"""
Regression tests for M-19: the CSP must close the directives that do not inherit
from default-src.

form-action and base-uri have no fallback. Without them an injected
`<form action="https://evil/">` still submits cross-origin even under an otherwise
strict policy — which is exactly the residual risk left by the tojson bug (C-4).
A wildcard img-src turns any HTML injection into a data exfiltration channel via
dangling markup.
"""

import pytest
from starlette.testclient import TestClient

from app.main import app


@pytest.fixture(scope="module")
def csp() -> dict[str, str]:
    """Parse the CSP header from a real response into {directive: value}."""
    with TestClient(app) as client:
        response = client.get("/health")
    header = response.headers["content-security-policy"]
    parsed = {}
    for directive in header.split(";"):
        directive = directive.strip()
        if directive:
            name, _, value = directive.partition(" ")
            parsed[name] = value.strip()
    return parsed


@pytest.mark.parametrize("directive, expected", [
    ("form-action", "'self'"),
    ("base-uri", "'self'"),
    ("object-src", "'none'"),
    ("frame-ancestors", "'none'"),
])
def test_non_inheriting_directives_are_present(csp, directive, expected):
    assert csp.get(directive) == expected, f"{directive} missing or too permissive"


def test_img_src_has_no_scheme_wildcard(csp):
    assert "https:" not in csp["img-src"], "wildcard img-src enables dangling-markup exfiltration"
    assert csp["img-src"] == "'self' data:"


def test_connect_src_has_no_scheme_wildcard(csp):
    # 'self' also covers same-origin ws:/wss: under CSP3, so the WebSocket endpoints
    # keep working without allowing connections to arbitrary hosts.
    assert "ws:" not in csp["connect-src"] and "wss:" not in csp["connect-src"]
    assert csp["connect-src"] == "'self'"


def test_script_src_is_nonce_based_without_unsafe(csp):
    assert "'unsafe-inline'" not in csp["script-src"]
    assert "'unsafe-eval'" not in csp["script-src"]
    assert "'nonce-" in csp["script-src"]


def test_nonce_differs_per_request():
    """A reused nonce would make the strict script-src pointless."""
    with TestClient(app) as client:
        first = client.get("/health").headers["content-security-policy"]
        second = client.get("/health").headers["content-security-policy"]
    assert first != second


def test_baseline_security_headers_present():
    with TestClient(app) as client:
        headers = client.get("/health").headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
