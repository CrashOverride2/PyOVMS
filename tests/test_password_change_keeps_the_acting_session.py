"""
Changing your own password ends every other session — and not your own.

`crud.user.update_user()` bumps token_version on a password change, which is what
makes every already-issued session cookie invalid: the right thing after a
suspected compromise. The 2FA routes on the profile page have always re-issued the
acting session's cookie afterwards (`_reissue_session_cookie`); the password route
did not. So the redirect to "Password updated successfully." was refused with the
old cookie, and the person who had just changed their password landed on the login
page, never seeing the message. The other sessions are still ended — that is the
half that matters for security — and this pins both halves.
"""

import re

import pytest
from fastapi.testclient import TestClient

from app import security
from app.database import Base, SessionLocal, engine, get_db
from app.main import app
from app.models import db as models_db
from app.security_manager import security_manager

PASSWORD = "CorrectHorse1!Battery"
NEW_PASSWORD = "AnotherHorse2!Staple"


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
    db.query(models_db.Vehicle).delete()
    db.query(models_db.SecurityEvent).delete()
    db.query(models_db.User).delete()
    db.commit()
    security_manager.blocked_ips.clear()
    security_manager.failed_attempts.clear()
    yield


def _client():
    def _get_db():
        session = SessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = _get_db
    return TestClient(app, base_url="https://testserver")


@pytest.fixture
def client():
    yield _client()
    app.dependency_overrides.clear()


@pytest.fixture
def other_browser():
    yield _client()
    app.dependency_overrides.clear()


def _make_user(db, username="alice"):
    user = models_db.User(
        username=username, email=f"{username}@example.com",
        hashed_password=security.get_password_hash(PASSWORD),
        is_active=True, is_admin=False, is_totp_enabled=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _csrf(page_text):
    token = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page_text) or \
        re.search(r'value="([^"]+)"[^>]*name="csrf_token"', page_text)
    assert token is not None
    return token.group(1)


def _login(client, username="alice", password=PASSWORD):
    response = client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": _csrf(client.get("/login").text)},
        follow_redirects=False,
    )
    assert response.status_code in (302, 303, 307), response.text


def _change_password(client):
    return client.post(
        "/profile/change-password",
        data={
            "current_password": PASSWORD, "new_password": NEW_PASSWORD,
            "confirm_new_password": NEW_PASSWORD, "csrf_token": _csrf(client.get("/profile").text),
        },
        follow_redirects=False,
    )


def test_the_acting_session_sees_the_success_message(client, db):
    _make_user(db)
    _login(client)

    response = _change_password(client)

    assert response.status_code == 303
    assert "success_message=Password+updated+successfully." in response.headers["location"]
    # The response carries a fresh cookie for the new token_version …
    assert "__Host-access_token" in response.headers.get("set-cookie", "")
    # … and the page it redirects to renders for this session.
    landed = client.get(response.headers["location"], follow_redirects=False)
    assert landed.status_code == 200, landed.headers.get("location")
    assert "Password updated successfully." in landed.text


def test_every_other_session_is_ended(client, other_browser, db):
    _make_user(db)
    _login(client)
    _login(other_browser)
    assert other_browser.get("/profile", follow_redirects=False).status_code == 200

    _change_password(client)

    refused = other_browser.get("/profile", follow_redirects=False)
    assert refused.status_code in (302, 303, 307)
    assert "/login" in refused.headers["location"]
    # The new password is what signs in from here on.
    _login(other_browser, password=NEW_PASSWORD)
    assert other_browser.get("/profile", follow_redirects=False).status_code == 200
