"""
The stronger second factor wins and switches the weaker one off.

An account with both a WebAuthn security key and TOTP used to be *redirected* to the
WebAuthn page while the TOTP route stayed wide open: the login handler set
pending_2fa_user_id before choosing a method, and the TOTP submit handler only checked
that the user had TOTP enabled. POSTing straight to /login/totp with a valid code
therefore produced a full session and stepped around the security key.

Tested against a real database rather than a stubbed session — the ranking is decided
by these queries, so stubbing them would test the stub.
"""

import inspect
from pathlib import Path

import pyotp
import pytest
from fastapi.testclient import TestClient

from app import crud, security
from app.database import Base, SessionLocal, engine, get_db
from app.main import app
from app.models import db as models_db
from app.security_manager import security_manager
from app.utils.two_factor import (
    SecondFactor,
    password_login_is_disabled,
    required_second_factor,
    totp_is_accepted_for,
)

PASSWORD = "CorrectHorse1!Battery"
REPO_ROOT = Path(__file__).resolve().parent.parent


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
    db.query(models_db.ApiKey).delete()
    db.query(models_db.WebAuthnCredential).delete()
    db.query(models_db.User).delete()
    db.query(models_db.BlockedIP).delete()
    db.query(models_db.SecurityFailure).delete()
    db.commit()
    security_manager.blocked_ips.clear()
    security_manager.failed_attempts.clear()
    security_manager._blocked_usernames.clear()
    security_manager._username_failures.clear()
    yield


def _user(db, totp=False):
    user = models_db.User(
        username="alice", email="alice@example.com",
        hashed_password=security.get_password_hash(PASSWORD),
        is_active=True, is_admin=False, is_totp_enabled=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    if totp:
        crud.user.enable_totp_for_user(db, user, pyotp.random_base32())
        db.refresh(user)
    return user


def _add_key(db, user, usage_mode):
    db.add(models_db.WebAuthnCredential(
        user_id=user.id, credential_id=f"cred-{usage_mode}-{user.id}".encode(),
        public_key=b"x", sign_count=0, is_active=True, usage_mode=usage_mode,
    ))
    db.commit()


# --- the ranking ------------------------------------------------------------------------

def test_webauthn_outranks_totp_when_both_are_registered(db):
    """The core rule. An attacker gets to pick, and would always pick the weaker."""
    user = _user(db, totp=True)
    _add_key(db, user, "2fa")

    assert required_second_factor(db, user) == SecondFactor.WEBAUTHN


def test_totp_is_required_when_it_is_the_only_factor(db):
    assert required_second_factor(db, _user(db, totp=True)) == SecondFactor.TOTP


def test_webauthn_is_required_when_it_is_the_only_factor(db):
    user = _user(db)
    _add_key(db, user, "2fa")

    assert required_second_factor(db, user) == SecondFactor.WEBAUTHN


def test_no_factor_when_none_is_registered(db):
    assert required_second_factor(db, _user(db)) == SecondFactor.NONE


def test_a_passwordless_key_is_not_a_second_factor(db):
    """'passwordless' replaces the password; it does not follow one."""
    user = _user(db)
    _add_key(db, user, "passwordless")

    assert required_second_factor(db, user) == SecondFactor.NONE


def test_a_deactivated_security_key_does_not_count(db):
    user = _user(db, totp=True)
    _add_key(db, user, "2fa")
    db.query(models_db.WebAuthnCredential).update({"is_active": False})
    db.commit()

    assert required_second_factor(db, user) == SecondFactor.TOTP


# --- what that means for TOTP --------------------------------------------------------------

def test_totp_is_refused_for_an_account_with_a_security_key(db):
    user = _user(db, totp=True)
    _add_key(db, user, "2fa")

    assert totp_is_accepted_for(db, user) is False


def test_totp_is_accepted_when_it_is_the_required_factor(db):
    assert totp_is_accepted_for(db, _user(db, totp=True)) is True


# --- passwordless-only accounts --------------------------------------------------------------

def test_password_login_disabled_for_passwordless_only_account(db):
    user = _user(db)
    _add_key(db, user, "passwordless")

    assert password_login_is_disabled(db, user) is True


def test_password_login_allowed_when_a_second_factor_exists(db):
    """A passwordless key plus TOTP still permits password + TOTP."""
    user = _user(db, totp=True)
    _add_key(db, user, "passwordless")

    assert password_login_is_disabled(db, user) is False


# --- the route itself ---------------------------------------------------------------------------

@pytest.fixture
def client():
    def _get_db():
        session = SessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = _get_db
    # https base URL: FORCE_SECURE_COOKIES defaults to True, so both the session
    # cookie and the access token are marked Secure and a plain http:// client would
    # silently drop them — every request would then look like a fresh session.
    yield TestClient(app, base_url="https://testserver", follow_redirects=False)
    app.dependency_overrides.clear()


def _login(client, csrf_from_page=True):
    """Perform the password step and return the client's session cookies."""
    page = client.get("/login")
    assert page.status_code == 200
    import re

    match = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert match, "login page must render a CSRF token"
    return client.post(
        "/login",
        data={"username": "alice", "password": PASSWORD, "csrf_token": match.group(1)},
    )


def test_totp_submit_is_refused_for_an_account_that_requires_webauthn(client, db):
    """
    The end-to-end regression: password step, then POST a *valid* TOTP code straight
    to /login/totp. It must not produce a session.
    """
    user = _user(db, totp=True)
    _add_key(db, user, "2fa")
    secret = crud.user.get_decrypted_totp_secret_for_user(
        db.query(models_db.User).filter_by(username="alice").first()
    )

    login = _login(client)
    assert login.status_code == 303
    assert "/login/webauthn" in login.headers["location"], "must steer to the security key"

    page = client.get("/login/totp")
    import re

    match = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    response = client.post(
        "/login/totp",
        data={"totp_code": pyotp.TOTP(secret).now(),
              "csrf_token": match.group(1) if match else ""},
    )

    assert response.status_code == 303
    assert "/login/webauthn" in response.headers["location"], (
        "a valid TOTP code must not satisfy an account whose factor is WebAuthn"
    )
    # The decisive assertion: no session was granted.
    assert not any(
        "access_token" in name for name in client.cookies.keys()
    ), "no access token may be issued by the downgraded path"


def test_totp_submit_still_works_when_totp_is_the_required_factor(client, db):
    """The guard must not break ordinary TOTP accounts."""
    _user(db, totp=True)
    secret = crud.user.get_decrypted_totp_secret_for_user(
        db.query(models_db.User).filter_by(username="alice").first()
    )

    login = _login(client)
    assert login.status_code == 303
    assert "/login/totp" in login.headers["location"]

    page = client.get("/login/totp")
    import re

    match = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    response = client.post(
        "/login/totp",
        data={"totp_code": pyotp.TOTP(secret).now(), "csrf_token": match.group(1)},
    )

    assert response.status_code == 303
    assert "/login/totp" not in response.headers["location"], "should proceed past 2FA"
    assert any("access_token" in name for name in client.cookies.keys())


# --- there must be exactly one place that ranks the factors -------------------------------------

def test_no_other_module_ranks_the_factors_itself():
    """
    Inline `usage_mode == '2fa'` checks outside app/utils/two_factor.py are how the
    enforcement points drifted apart in the first place.
    """
    offenders = []
    for path in (REPO_ROOT / "app").rglob("*.py"):
        if path.name in ("two_factor.py",) or "webauthn" in path.name:
            continue  # the WebAuthn router legitimately queries its own credentials
        text = path.read_text()
        if "usage_mode == '2fa'" in text or 'usage_mode == "2fa"' in text:
            offenders.append(str(path.relative_to(REPO_ROOT)))

    assert offenders == [], (
        f"these files rank 2FA methods themselves instead of using "
        f"app.utils.two_factor: {offenders}"
    )


def test_enforcement_points_consult_the_shared_ranking():
    from app.routers.api import device_auth
    from app.routers.ui import auth

    assert "totp_is_accepted_for(db, user)" in inspect.getsource(
        auth.ui_login_totp_submit_route)
    assert "required_second_factor(db, user)" in inspect.getsource(
        auth.ui_login_submit_route)
    assert "required_second_factor" in inspect.getsource(device_auth._requires_web_flow)
