"""
A cookie authenticates the two mutating blocked-IP endpoints, so a CSRF token has to.

`POST /api/v1/security/blocked-ips` and `DELETE /api/v1/security/blocked-ips/{ip}` are
reachable with either an API key or an admin session cookie. The key half needs no
token — the browser never attaches it, so a cross-site page cannot authenticate with
one. The cookie half is the opposite: the browser sends it with whatever request an
attacker's page provokes, and these two endpoints block and unblock IP addresses.

The bar was low rather than absent — a JSON body forces a preflight this deployment's
CORS policy refuses — but that is a property of what browsers make awkward, not of the
endpoint.

The static scan at the bottom is the half that lasts, and its scope is wider than these
two routes: every mutating handler under app/routers that any cookie dependency can
authenticate must either take the CSRF-aware dependency or call verify_csrf_token
itself. It reads the decorator as well as the signature, because this tree declares auth
both ways and the API router uses the decorator form exclusively.
"""

import ast
import datetime
import pathlib
import re
from typing import NamedTuple

import pytest
from fastapi.testclient import TestClient

from app import crud, security
from app.database import Base, SessionLocal, engine, get_db
from app.main import app
from app.models import db as models_db
from app.security_manager import security_manager

PASSWORD = "CorrectHorse1!Battery"
BLOCKED_IPS_URL = "/api/v1/security/blocked-ips"
# Never the test client's own address: blocking that would make every later request in
# the test 429 from SecurityMiddleware.
TARGET_IP = "203.0.113.5"

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
ROUTERS = REPO_ROOT / "app" / "routers"


@pytest.fixture(scope="module", autouse=True)
def _schema():
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(autouse=True)
def _clean(db):
    db.query(models_db.BlockedIP).delete()
    db.query(models_db.ApiKey).delete()
    db.query(models_db.User).delete()
    db.query(models_db.SecurityFailure).delete()
    db.commit()
    security_manager.blocked_ips.clear()
    security_manager.failed_attempts.clear()
    security_manager._blocked_usernames.clear()
    security_manager._username_failures.clear()
    yield
    security_manager.blocked_ips.clear()


@pytest.fixture
def client():
    """https, because FORCE_SECURE_COOKIES marks the session cookie Secure — over http
    the client stores it and never sends it back, and the login silently does nothing."""
    def _get_db():
        session = SessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = _get_db
    yield TestClient(app, base_url="https://testserver")
    app.dependency_overrides.clear()


def _make_admin(db, username="root"):
    user = models_db.User(
        username=username,
        email=f"{username}@example.com",
        hashed_password=security.get_password_hash(PASSWORD),
        is_active=True,
        is_admin=True,
        is_totp_enabled=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    db.commit()
    return user


def _login(client, username="root"):
    """Log in through the real form, so the session is what a browser would hold."""
    page = client.get("/login")
    token = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page.text) or \
        re.search(r'value="([^"]+)"[^>]*name="csrf_token"', page.text)
    assert token is not None, "no csrf_token on the login page"
    response = client.post(
        "/login",
        data={"username": username, "password": PASSWORD, "csrf_token": token.group(1)},
        follow_redirects=False,
    )
    assert response.status_code in (302, 303, 307), response.text


def _session_csrf(client) -> str:
    return client.get("/csrf-token/refresh").json()["csrf_token"]


def _existing_block(db) -> models_db.BlockedIP:
    now = datetime.datetime.now(datetime.timezone.utc)
    row = models_db.BlockedIP(
        ip=TARGET_IP,
        reason="test",
        created_at=now,
        unblock_at=now + datetime.timedelta(hours=1),
    )
    db.add(row)
    db.commit()
    security_manager.blocked_ips[TARGET_IP] = row.unblock_at
    return row


def _blocked(db) -> bool:
    return db.query(models_db.BlockedIP).filter_by(ip=TARGET_IP).count() > 0


# --- the cookie half needs a token -----------------------------------------------

def test_a_session_cannot_block_an_ip_without_the_token(client, db):
    _make_admin(db)
    _login(client)

    response = client.post(BLOCKED_IPS_URL, json={"ip": TARGET_IP, "duration_minutes": 60})

    assert response.status_code == 403
    assert "CSRF" in response.json()["detail"]
    assert not _blocked(db), "the block was created despite the rejection"


def test_a_session_cannot_unblock_an_ip_without_the_token(client, db):
    _make_admin(db)
    _login(client)
    _existing_block(db)

    response = client.delete(f"{BLOCKED_IPS_URL}/{TARGET_IP}")

    assert response.status_code == 403
    assert _blocked(db), "the block was lifted despite the rejection"


def test_a_forged_token_is_refused(client, db):
    _make_admin(db)
    _login(client)

    response = client.post(
        BLOCKED_IPS_URL,
        json={"ip": TARGET_IP, "duration_minutes": 60},
        headers={"X-CSRF-Token": "garbage"},
    )

    assert response.status_code == 403
    assert not _blocked(db)


def test_a_session_with_the_token_still_works(client, db):
    _make_admin(db)
    _login(client)

    created = client.post(
        BLOCKED_IPS_URL,
        json={"ip": TARGET_IP, "duration_minutes": 60},
        headers={"X-CSRF-Token": _session_csrf(client)},
    )

    assert created.status_code == 201, created.text
    assert created.json()["ip"] == TARGET_IP


def test_several_actions_off_one_rendered_page_all_succeed(client, db):
    """The reason the guard verifies without rotating.

    The admin console holds one token and fires action after action against it. Rotating
    would invalidate it after the next request, and the third block in a row would fail
    with a mismatch on a page the admin never left.
    """
    _make_admin(db)
    _login(client)
    token = _session_csrf(client)

    for n in range(3):
        response = client.post(
            BLOCKED_IPS_URL,
            json={"ip": f"203.0.113.{10 + n}", "duration_minutes": 60},
            headers={"X-CSRF-Token": token},
        )
        assert response.status_code == 201, f"attempt {n + 1}: {response.text}"


# --- the API-key half must stay token-free ----------------------------------------

def test_an_api_key_needs_no_token(client, db):
    """A key is not ambient authority: no browser attaches it, so there is nothing for a
    token to protect against — and requiring one would break every non-browser caller."""
    admin = _make_admin(db)
    _, key = crud.apikey.create_api_key(db, admin.id, "admin-key")
    db.commit()

    response = client.post(
        BLOCKED_IPS_URL,
        json={"ip": TARGET_IP, "duration_minutes": 60},
        headers={"X-API-Key": key},
    )

    assert response.status_code == 201, response.text


# --- the guard that outlives this change ------------------------------------------

# Dependencies that authenticate from the session cookie. Any one of them on a mutating
# route means the browser attaches the credential to whatever request a third-party page
# provokes, which is the whole precondition for CSRF.
COOKIE_AUTH_DEPENDENCIES = (
    "require_admin_user_from_cookie_or_api",
    "require_admin_user_from_cookie",
    "require_current_user_from_cookie_fully_authenticated",
    "get_user_from_request_cookie",
)
# Not in the tuple above, and it does not need to be: two of those names are prefixes of
# this one, so a route taking the guarded dependency is already counted as
# cookie-reachable. It is listed separately because it is what makes such a route safe.
CSRF_DEPENDENCY = "require_admin_user_from_cookie_or_api_with_csrf"

ROUTE_METHODS = ("post", "put", "delete", "patch", "get")
MUTATING_METHODS = ("post", "put", "delete", "patch")


class Route(NamedTuple):
    where: str
    method: str
    declaration: str
    verifies_csrf: bool

    @property
    def cookie_reachable(self) -> bool:
        # CSRF_DEPENDENCY contains the shorter names, so it satisfies this too — a
        # guarded route is still a cookie-reachable one, it just also has the guard.
        return any(d in self.declaration for d in COOKIE_AUTH_DEPENDENCIES)

    @property
    def guarded(self) -> bool:
        return CSRF_DEPENDENCY in self.declaration or self.verifies_csrf


def _calls_verify_csrf_token(node: ast.AST) -> bool:
    """Whether the handler actually calls verify_csrf_token().

    Matched as an AST call, not as a substring of the source. The name appears in prose
    in several docstrings along this path, and a docstring is not a check.
    """
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        func = child.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        if name == "verify_csrf_token":
            return True
    return False


def _route_handlers():
    """Every route handler under app/routers.

    Both halves of the declaration are read, and that is the point. Auth is spelled two
    ways in this tree: as a signature parameter (`user: User = Depends(...)`, the style
    in routers/api/security_events.py) and as `dependencies=[Depends(...)]` on the
    decorator (the style used for all 18 routes in routers/api/main.py). A scan that
    reads only the signature is blind to every route written the second way — which is
    most of the API surface, and the obvious place for the next dual-auth route to land.
    """
    for path in sorted(ROUTERS.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text())):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            decorators = " ".join(ast.unparse(d) for d in node.decorator_list)
            method = next((m for m in ROUTE_METHODS if f".{m}(" in decorators), None)
            if method is None:
                continue
            yield Route(
                where=f"{path.relative_to(REPO_ROOT)}::{node.name}",
                method=method,
                declaration=f"{ast.unparse(node.args)} {decorators}",
                verifies_csrf=_calls_verify_csrf_token(node),
            )


ALL_ROUTES = list(_route_handlers())
COOKIE_MUTATING_ROUTES = [
    r for r in ALL_ROUTES if r.cookie_reachable and r.method in MUTATING_METHODS
]


def test_the_scan_still_finds_the_routes_it_is_meant_to_guard():
    """A guard whose subject silently becomes an empty set passes forever."""
    assert len(ALL_ROUTES) >= 100, (
        f"only {len(ALL_ROUTES)} route handlers found — the scan has stopped matching "
        "how routes are declared in this tree."
    )
    assert len(COOKIE_MUTATING_ROUTES) >= 30, (
        f"only {len(COOKIE_MUTATING_ROUTES)} cookie-reachable mutating routes found — "
        "the dependency names in COOKIE_AUTH_DEPENDENCIES have probably been renamed."
    )
    found = {r.where for r in COOKIE_MUTATING_ROUTES}
    for expected in ("security_events.py::block_ip", "security_events.py::unblock_ip"):
        assert any(expected in w for w in found), (
            f"{expected} is no longer in the scanned set, so the two routes this file "
            "exists for are no longer being checked."
        )


def test_every_cookie_reachable_mutating_route_verifies_csrf():
    """Either the CSRF-aware dependency, or a verify_csrf_token() call of its own.

    Note what is deliberately *not* accepted as a guard: the router-level
    Depends(csrf_protect) on the UI router. It reads the token from form data and
    returns early for `Content-Type: application/json`, so a JSON handler that leans on
    it alone is unprotected — which is exactly the shape the two blocked-IP endpoints
    had. Every UI route today also calls verify_csrf_token itself; a future one that
    does not should fail here rather than inherit a check that skips its content type.
    """
    offenders = [
        f"{r.where} ({r.method.upper()})" for r in COOKIE_MUTATING_ROUTES if not r.guarded
    ]
    assert offenders == [], (
        "these routes change state and accept a session cookie, so a cross-site page can "
        "trigger them with the user's own credentials. Use "
        f"{CSRF_DEPENDENCY} or call verify_csrf_token() in the handler: "
        + ", ".join(offenders)
    )
