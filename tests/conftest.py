"""
Shared test setup.

These tests are deliberately import-level and offline: no running server, no broker, no
network. Everything asserted here is a property of the code itself, so the suite stays
runnable in CI and in a pre-commit hook. The end-to-end black-box checks live in
doc/security/test_security_features.py and need a live server.
"""

import base64
import os
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# app.config reads the environment at import time. Pin the values the tests depend on so
# a developer's local .env cannot change the outcome of a security assertion.
os.environ.setdefault("SECRET_KEY_JWT", "t" * 64)
os.environ.setdefault("SECRET_KEY_SESSION", "s" * 64)
os.environ.setdefault("FORWARDED_ALLOW_IPS", "127.0.0.1")
os.environ.setdefault("LOG_FILE", "")
# Must be a structurally valid Fernet key or app.utils.crypto refuses to initialise.
os.environ.setdefault("TOTP_ENCRYPTION_KEY", base64.urlsafe_b64encode(b"0" * 32).decode())

# Fixed Ed25519 session key pair. Deterministic so a signed token can be compared
# across tests; startup aborts without a usable pair, and the two halves must match.
_TEST_JWT_SEED = b"\x11" * 32


def _test_jwt_keypair() -> tuple[str, str]:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.from_private_bytes(_TEST_JWT_SEED)
    public_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(_TEST_JWT_SEED).decode(), base64.b64encode(public_raw).decode()


_priv, _pub = _test_jwt_keypair()
os.environ.setdefault("JWT_PRIVATE_KEY", _priv)
os.environ.setdefault("JWT_PUBLIC_KEY", _pub)

# Never point the suite at the developer's ovms_py.db: starting the app runs Alembic
# migrations, and a test run must not be able to migrate or write real data. Set this
# unconditionally — a stray DATABASE_URL in the environment must not win here.
_TEST_DB = Path(tempfile.gettempdir()) / "pyovms_test_suite.db"
os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DB}"

# Start every session from an empty file. The database outlives a run, so a schema
# from an older checkout survives into a newer one: after a migration adds a column,
# the first run against a stale file fails with "no such column" in whichever module
# happens to touch that table first, and then silently repairs itself once a module
# that boots the app runs Alembic. That is a confusing half-hour for anyone who hits
# it, and it hides real breakage behind a rerun.
if _TEST_DB.exists():
    _TEST_DB.unlink()

# TrustedHostMiddleware derives the accepted Host values from SERVER_BASE_URL, and
# starlette's TestClient sends `Host: testserver`. Naming the test server here is the
# honest way to satisfy it: the alternative — allowing an extra host in production
# code because the tests use it — is how that middleware stops meaning anything.
os.environ.setdefault("SERVER_BASE_URL", "http://testserver")

# Keep the MQTT auth manager from writing broker files anywhere real.
os.environ.setdefault("MQTT_PASSWD_FILE", "")
os.environ.setdefault("MQTT_ACL_FILE", "")


from collections import namedtuple as _namedtuple

import pytest as _pytest

RouteInfo = _namedtuple("RouteInfo", "path methods name")


@_pytest.fixture(autouse=True)
def _clear_outbound_dns_cache():
    """The SSRF guard memoises resolution verdicts, so they outlive a test.

    Two tests that stub getaddrinfo for the same hostname would otherwise share one
    answer, and the second would pass on the strength of the first one's stub without
    ever exercising its own.
    """
    from app.notifications import outbound

    outbound.clear_dns_cache()
    yield
    outbound.clear_dns_cache()


def iter_http_routes(app):
    """
    Every route reachable through `app`, with its full URL path, on any Starlette version.

    `app.routes` is not a flat list of routes and its shape is not stable across versions.
    Starlette 1.5 — the pinned version, so the one a deployment runs — stopped copying an
    included router's routes into the parent. It wraps them in a `_IncludedRouter` whose
    own `path` is None, and the routes underneath it carry their path *without* the prefix
    they were included under. Read naively, `app.routes` on this server yields nine
    entries: /static, /health, three docs endpoints, and four opaque wrappers hiding every
    API and UI route behind them.

    Both mistakes are worth naming, because the second is the quiet one:

      * Not walking into the wrapper hides ~100 routes. Tests written against the
        development virtualenv, where the routes happened to be flat, passed there and
        failed against requirements.txt — the combination that ships.
      * Walking into it but ignoring `include_context.prefix` yields '/suggest-id' instead
        of '/vehicle/suggest-id'. That does not fail loudly: a smoke test then requests
        URLs that do not exist, gets 404s, and reports green while testing nothing.

    So the prefix is accumulated on the way down, and the result is compared against the
    other layout in tests/test_route_inventory.py.
    """
    collected = []

    def walk(routes, prefix):
        for route in routes:
            context = getattr(route, "include_context", None)
            if context is not None:                      # Starlette >= 1.5 wrapper
                inner = getattr(context, "included_router", None)
                inner = inner if inner is not None else route.original_router
                walk(inner.routes, prefix + (context.prefix or ""))
                continue

            nested = getattr(route, "routes", None)
            if nested:                                   # Mount, and older layouts
                walk(nested, prefix + (getattr(route, "path", "") or ""))
                continue

            path = getattr(route, "path", None)
            if path is None:
                continue
            collected.append(
                RouteInfo(
                    path=prefix + path,
                    methods=frozenset(getattr(route, "methods", None) or ()),
                    name=getattr(route, "name", None),
                )
            )

    walk(app.routes, "")
    return collected
