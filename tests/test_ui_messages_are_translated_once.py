"""
User-facing text that reached the browser untranslated, or twice.

Driven over HTTP with `Accept-Language: de`, because each of these looked fine in
the source and in the catalogue and was only wrong on the rendered page:

* the login form's generic error was an English literal beside a bound `_` — the
  most frequent message of the whole UI, in English on a German page;
* the login pages rendered their own banner for `?error_message=` *and* inherited
  the toast base.html renders for the same parameter, so every error showed twice;
* a label removed from a template and later put back stays untranslated: pybabel
  keeps the old translation as an obsolete entry and creates a new, empty one next
  to it, and `--check` reports nothing (`Real-time Status:` on the vehicle page);
* a pydantic ValidationError's `errors()` is a list; two admin routes indexed it as
  a dict and answered a too-short auto-provisioning key with a 500;
* `page_title` is translated by the template (`_(page_title)`), which only works
  when the literal in the router was extracted — so the router marks it with N_.
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
GERMAN = {"Accept-Language": "de"}


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
    db.query(models_db.AutoProvisionProfile).delete()
    db.query(models_db.Vehicle).delete()
    db.query(models_db.ApiKey).delete()
    db.query(models_db.SecurityEvent).delete()
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
    yield TestClient(app, base_url="https://testserver")
    app.dependency_overrides.clear()


def _make_user(db, username="alice", *, admin=False):
    user = models_db.User(
        username=username, email=f"{username}@example.com",
        hashed_password=security.get_password_hash(PASSWORD),
        is_active=True, is_admin=admin, is_totp_enabled=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _make_vehicle(db, owner, vehicle_id="I18NCAR"):
    vehicle = models_db.Vehicle(vehicle_id=vehicle_id, owner_id=owner.id,
                                protocol="both", encrypted_server_password=b"x")
    db.add(vehicle)
    db.commit()
    db.refresh(vehicle)
    return vehicle


def _csrf_from(page_text: str) -> str:
    token = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page_text) or \
        re.search(r'value="([^"]+)"[^>]*name="csrf_token"', page_text)
    assert token is not None, "no csrf_token on the page"
    return token.group(1)


def _login(client, username="alice", password=PASSWORD):
    page = client.get("/login", headers=GERMAN)
    return client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": _csrf_from(page.text)},
        headers=GERMAN, follow_redirects=False,
    )


def _session_csrf(client) -> str:
    return client.get("/csrf-token/refresh").json()["csrf_token"]


# ---------------------------------------------------------------------------
# Flash messages: translated, and shown once
# ---------------------------------------------------------------------------

def test_a_wrong_password_is_answered_in_the_browsers_language(client, db):
    _make_user(db)
    response = _login(client, password="not-the-password")
    assert response.status_code == 303
    location = response.headers["location"]
    assert "Ung%C3%BCltige+Anmeldedaten" in location, location
    assert "Invalid+credentials" not in location


@pytest.mark.parametrize("path", ["/login", "/forgot-password"])
def test_an_error_on_an_auth_page_is_shown_exactly_once(client, path):
    page = client.get(f"{path}?error_message=PROBE_MESSAGE_7f3a", headers=GERMAN)
    assert page.status_code == 200
    assert page.text.count("PROBE_MESSAGE_7f3a") == 1, (
        f"{path} renders the flash message {page.text.count('PROBE_MESSAGE_7f3a')} times; "
        "the toast in base.html is the one place for it"
    )
    assert 'data-toast-kind="error"' in page.text


# ---------------------------------------------------------------------------
# A label that came back after being obsoleted
# ---------------------------------------------------------------------------

def test_the_vehicle_page_connection_label_is_translated(client, db):
    owner = _make_user(db)
    _make_vehicle(db, owner)
    _login(client)
    page = client.get("/vehicle/I18NCAR", headers=GERMAN)
    assert page.status_code == 200, page.text[:500]
    assert "Echtzeit-Status:" in page.text
    assert "Real-time Status:" not in page.text
    # the metric group labels the "All Metrics" tab shows are handed to the page
    # translated; the English names stay the keys
    assert "Hauptbatterie" in page.text


def test_no_live_msgid_is_shadowed_by_an_obsolete_entry():
    """pybabel keeps a removed translation as `#~ msgid` and, when the string comes
    back, adds a new empty entry beside it instead of reviving the old one. The
    catalogue then passes `--check` with a hole in it."""
    from babel.messages.pofile import read_po
    from pathlib import Path

    for po in sorted(Path("app/translations").glob("*/LC_MESSAGES/messages.po")):
        with po.open("rb") as handle:
            catalog = read_po(handle)
        live_ids = {m.id for m in catalog if m.id}
        shadowed = sorted(i for i in catalog.obsolete if i in live_ids)
        assert shadowed == [], f"{po}: obsolete entries shadow live msgids: {shadowed}"
        empty = sorted(m.id for m in catalog if m.id and not m.string)
        assert empty == [], f"{po}: untranslated: {empty}"
        fuzzy = sorted(m.id for m in catalog if m.id and m.fuzzy)
        assert fuzzy == [], f"{po}: fuzzy (unreviewed) entries: {fuzzy}"


# ---------------------------------------------------------------------------
# pydantic errors reach the page as one translated line, never as a 500
# ---------------------------------------------------------------------------

def test_a_short_provisioning_key_is_a_flash_message_not_a_500(client, db):
    _make_user(db, "root", admin=True)
    _login(client, "root")
    response = client.post(
        "/admin/autoprovision/add",
        data={
            "ap_key": "short", "target_vehicle_id": "APCAR",
            "target_server_password": "SecretPassword12", "csrf_token": _session_csrf(client),
        },
        headers=GERMAN, follow_redirects=False,
    )
    assert response.status_code == 303, response.text[:300]
    location = response.headers["location"]
    assert "error_message=" in location
    assert "Value+error" not in location, location
    assert "mindestens+12+Zeichen" in location, location


def test_the_registration_form_names_the_password_rule_in_german(client, db, monkeypatch):
    from app.config import settings
    monkeypatch.setattr(settings, "ALLOW_USER_REGISTRATION", True)
    monkeypatch.setattr(settings, "EMAIL_HOST", "smtp.example.test")
    monkeypatch.setattr(settings, "EMAIL_SENDER", "noreply@example.test")
    page = client.get("/register", headers=GERMAN)
    assert page.status_code == 200
    # long enough for the Field constraint, refused by the policy validator
    response = client.post(
        "/register",
        data={"username": "newbie", "email": "newbie@example.com", "password": "weakweakweakweak",
              "confirm_password": "weakweakweakweak", "csrf_token": _csrf_from(page.text)},
        headers=GERMAN,
    )
    assert response.status_code == 200
    assert "Das Passwort muss 12 bis 128 Zeichen" in response.text
    assert "Value error" not in response.text

    # pydantic's own constraint message, rendered from a template of ours
    response = client.post(
        "/register",
        data={"username": "newbie", "email": "newbie@example.com", "password": "weak",
              "confirm_password": "weak", "csrf_token": _csrf_from(response.text)},
        headers=GERMAN,
    )
    assert response.status_code == 200
    assert "Password: muss mindestens 12 Zeichen lang sein" in response.text
    assert "String should have" not in response.text


# ---------------------------------------------------------------------------
# Page titles
# ---------------------------------------------------------------------------

def test_every_page_title_a_router_passes_is_marked_or_translated():
    """`page_title` is rendered through `_(page_title)`; a bare literal in the router
    is invisible to pybabel and stays English."""
    from pathlib import Path

    offenders = []
    for path in sorted(Path("app/routers/ui").glob("*.py")):
        for lineno, line in enumerate(path.read_text().splitlines(), 1):
            m = re.search(r'"page_title":\s*(.+?),?\s*$', line)
            if not m:
                continue
            value = m.group(1).rstrip(",").strip()
            if value.startswith(("N_(", "_(", "common_vars[\"_\"](")):
                continue
            offenders.append(f"{path.name}:{lineno}: {value}")
    assert offenders == [], "page_title literals that pybabel cannot extract:\n" + "\n".join(offenders)
