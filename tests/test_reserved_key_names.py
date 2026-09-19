"""
User input can never claim a server-managed API key name.

Two prefixes carry behaviour: `temp-karto-delete-` is exempt from the per-user quota
and hidden from the profile page, and `device-` opts a key into the sliding expiry. All of that used to be derived from the name alone, which meant a user
who named their key "temp-karto-delete-x" inherited the behaviour (finding N-3).

The guard exists in two layers — a Pydantic validator on the JSON API and a check in
crud.apikey.create_api_key() that also covers the HTML form. This file drives both
*entry points over HTTP*, because the form path was previously only ever asserted by
reading the code, and the difference between "the CRUD raises" and "the route turns
that into a refusal" is exactly the kind of gap that reading does not catch.
"""

import re

import pytest
from fastapi.testclient import TestClient

from app import crud, security
from app.crud.apikey import DEVICE_KEY_NAME_PREFIX, INTERNAL_KEY_NAME_PREFIXES
from app.database import Base, SessionLocal, engine, get_db
from app.main import app
from app.models import db as models_db
from app.security_manager import security_manager

PASSWORD = "CorrectHorse1!Battery"

ALL_RESERVED = INTERNAL_KEY_NAME_PREFIXES + (DEVICE_KEY_NAME_PREFIX,)


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


@pytest.fixture
def client():
    def _get_db():
        session = SessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = _get_db
    # https: FORCE_SECURE_COOKIES marks the session and access cookies Secure, and a
    # plain http client would silently drop them — the login below would never stick.
    yield TestClient(app, base_url="https://testserver", follow_redirects=False)
    app.dependency_overrides.clear()


@pytest.fixture
def logged_in(client, db):
    user = models_db.User(
        username="alice", email="alice@example.com",
        hashed_password=security.get_password_hash(PASSWORD),
        is_active=True, is_admin=False, is_totp_enabled=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    page = client.get("/login")
    token = re.search(r'name="csrf_token" value="([^"]+)"', page.text).group(1)
    response = client.post(
        "/login",
        data={"username": "alice", "password": PASSWORD, "csrf_token": token},
    )
    assert response.status_code == 303, "test setup: login must succeed"
    return user


def _csrf(client, path="/profile"):
    page = client.get(path)
    match = re.search(r'name="csrf_token" value="([^"]+)"', page.text)
    assert match, f"no CSRF token on {path}"
    return match.group(1)


# --- the HTML form -----------------------------------------------------------------------

@pytest.mark.parametrize("prefix", ALL_RESERVED)
def test_the_profile_form_refuses_a_reserved_prefix(client, db, logged_in, prefix):
    """
    The path that was only ever verified by reading the code: the CRUD layer raises
    ValueError and the route has to turn that into a refusal rather than a 500.
    """
    response = client.post(
        "/profile/apikeys/create",
        data={"key_name": f"{prefix}mine", "expires_in_days": "",
              "csrf_token": _csrf(client)},
    )

    assert response.status_code == 303
    assert "error_message" in response.headers["location"]
    assert db.query(models_db.ApiKey).count() == 0, "no key may be created"


@pytest.mark.parametrize("name", [
    "TEMP-KARTO-DELETE-mine",  # case must not matter
    "  device-mine",         # nor leading whitespace
    "\ttemp-karto-delete-x",
])
def test_the_profile_form_is_not_fooled_by_casing_or_padding(client, db, logged_in, name):
    response = client.post(
        "/profile/apikeys/create",
        data={"key_name": name, "expires_in_days": "", "csrf_token": _csrf(client)},
    )

    assert response.status_code == 303
    assert "error_message" in response.headers["location"]
    assert db.query(models_db.ApiKey).count() == 0


def test_an_ordinary_name_still_works_through_the_form(client, db, logged_in):
    """The guard must not block legitimate names — including near-misses."""
    for name in ("my laptop", "device", "temp-karto"):
        response = client.post(
            "/profile/apikeys/create",
            data={"key_name": name, "expires_in_days": "", "csrf_token": _csrf(client)},
        )
        assert response.status_code == 303
        assert "error_message" not in response.headers["location"], f"{name!r} was refused"

    assert db.query(models_db.ApiKey).count() == 3


# --- the JSON API -------------------------------------------------------------------------

@pytest.mark.parametrize("prefix", ALL_RESERVED)
def test_the_json_api_refuses_a_reserved_prefix(client, db, logged_in, prefix):
    user = logged_in
    key, plain = crud.apikey.create_api_key(db, user_id=user.id, name="bootstrap")

    response = client.post(
        "/api/v1/apikeys",
        json={"name": f"{prefix}mine"},
        headers={"X-API-Key": plain},
    )

    assert response.status_code == 422
    assert db.query(models_db.ApiKey).count() == 1, "only the bootstrap key may exist"


# --- the server's own callers must still be able to use them --------------------------------

def test_server_issued_names_are_still_possible(db):
    """
    The guard blocks user input, not the server. If this breaks, Karto deletion and
    device provisioning stop working — so it is asserted alongside the refusals.
    """
    user = models_db.User(
        username="bob", email="bob@example.com",
        hashed_password=security.get_password_hash(PASSWORD), is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    internal, _ = crud.apikey.create_api_key(
        db, user_id=user.id, name="temp-karto-delete-bob-1",
        purpose=crud.apikey.KeyPurpose.INTERNAL)
    device, _ = crud.apikey.create_api_key(
        db, user_id=user.id, name="device-ios-1",
        purpose=crud.apikey.KeyPurpose.DEVICE)

    assert internal.name.startswith("temp-karto-delete-")
    assert device.name.startswith(DEVICE_KEY_NAME_PREFIX)


def test_every_behavioural_prefix_is_reserved():
    """
    A prefix that carries behaviour but is not reserved is the N-3 bug returning. This
    fails if someone adds a new prefix to INTERNAL_KEY_NAME_PREFIXES or introduces
    another marker without also blocking it from user input.
    """
    from app.crud import apikey

    for prefix in ALL_RESERVED:
        assert apikey.is_reserved_key_name(f"{prefix}anything"), (
            f"{prefix!r} carries behaviour but is not blocked from user input"
        )
