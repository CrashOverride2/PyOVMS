"""
Command favorites of the vehicle terminal: saved per user, sent with one click.

The two AJAX routes (`/terminal/favorites`, `/terminal/favorites/{id}/delete`) and
the page that renders the list are driven over HTTP through the real login form.
What is pinned here:

* a favorite belongs to the user who saved it — another user's id is 404, an
  administrator's too, and nothing of theirs is touched;
* the cap refuses with 409 instead of evicting;
* label and command are stripped, single-line and bounded, and a label that tries
  to leave the <script> block stays inside it;
* the CSRF token is checked, and every answer carries a fresh one;
* an id past the Integer column is 422, not an OverflowError out of sqlite3.
"""

import json
import re

import pytest
from fastapi.testclient import TestClient

from app import crud, security
from app.crud import command_favorite as crud_favorite
from app.database import Base, SessionLocal, engine, get_db
from app.main import app
from app.models import db as models_db
from app.security_manager import security_manager

PASSWORD = "CorrectHorse1!Battery"
BREAKOUT = "</script><img src=x onerror=alert(1)>"


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
    db.query(models_db.CommandFavorite).delete()
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


def _make_vehicle(db, owner, vehicle_id="FAVCAR"):
    vehicle = models_db.Vehicle(vehicle_id=vehicle_id, owner_id=owner.id,
                                protocol="both", encrypted_server_password=b"x")
    db.add(vehicle)
    db.commit()
    db.refresh(vehicle)
    return vehicle


def _login(client, username="alice"):
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


def _create(client, label, command, csrf=None):
    return client.post(
        "/terminal/favorites",
        data={"label": label, "command": command, "csrf_token": csrf or _session_csrf(client)},
    )


def _delete(client, favorite_id, csrf=None):
    return client.post(
        f"/terminal/favorites/{favorite_id}/delete",
        data={"csrf_token": csrf or _session_csrf(client)},
    )


def _rows(db, owner_id):
    return crud_favorite.list_favorites(db, owner_id)


def _page_favorites(client, vehicle_id="FAVCAR"):
    """The list as the page hands it to Alpine, parsed back out of the script block."""
    page = client.get(f"/vehicle/{vehicle_id}")
    assert page.status_code == 200, page.text
    match = re.search(r"commandFavorites:\s*(\[.*?\]),\n", page.text)
    assert match is not None, "commandFavorites missing from vehicleDetailConfig"
    return page.text, json.loads(match.group(1))


# --- create ------------------------------------------------------------------------------

def test_a_favorite_is_stored_and_appended_in_order(client, db):
    user = _make_user(db)
    _login(client)

    first = _create(client, "Status", "stat")
    second = _create(client, "Wake", "wakeup")

    assert first.status_code == 201, first.text
    assert second.status_code == 201, second.text
    body = second.json()
    assert body["ok"] is True
    assert body["favorite"]["label"] == "Wake"
    assert body["favorite"]["command"] == "wakeup"
    assert body["csrf_token"], "every answer carries the rotated token"
    rows = _rows(db, user.id)
    assert [(r.label, r.command, r.position) for r in rows] == [("Status", "stat", 0), ("Wake", "wakeup", 1)]


def test_label_and_command_are_stripped(client, db):
    user = _make_user(db)
    _login(client)

    response = _create(client, "  Status  ", "   stat   ")

    assert response.status_code == 201, response.text
    row = _rows(db, user.id)[0]
    assert (row.label, row.command) == ("Status", "stat")


def test_the_page_renders_the_users_favorites_into_the_terminal_config(client, db):
    user = _make_user(db)
    _make_vehicle(db, user)
    _login(client)
    _create(client, "Status", "stat")

    _, favorites = _page_favorites(client)

    assert [f["command"] for f in favorites] == ["stat"]
    assert set(favorites[0]) == {"id", "label", "command", "position"}


def test_favorites_are_the_users_not_the_vehicles(client, db):
    user = _make_user(db)
    _make_vehicle(db, user, "CARONE")
    _make_vehicle(db, user, "CARTWO")
    _login(client)
    _create(client, "Status", "stat")

    _, on_one = _page_favorites(client, "CARONE")
    _, on_two = _page_favorites(client, "CARTWO")

    assert [f["label"] for f in on_one] == ["Status"]
    assert on_one == on_two


def test_a_label_cannot_leave_the_script_block(client, db):
    user = _make_user(db)
    _make_vehicle(db, user)
    _login(client)
    assert _create(client, BREAKOUT[:40], BREAKOUT).status_code == 201

    page, favorites = _page_favorites(client)

    assert "</script><img" not in page
    assert "\\u003c/script\\u003e" in page
    assert favorites[0]["command"] == BREAKOUT


@pytest.mark.parametrize("label, command", [
    ("", "stat"),
    ("   ", "stat"),
    ("Status", ""),
    ("x" * 41, "stat"),
    ("Status", "x" * 201),
    ("Status", "stat\nwakeup"),
    ("Sta\x00tus", "stat"),
    ("Status", "stat\x7f"),
    # Past C0: a C1 control and the Unicode line/paragraph separators, which
    # `ord(ch) < 32` let through and which log viewers read as line breaks. Mid-text,
    # because at either end str.strip() removes them as whitespace before the check.
    ("Sta\x85tus", "stat"),
    ("Status", "stat\u2028wakeup"),
    ("Sta\u2029tus", "stat"),
])
def test_bad_input_is_refused_and_nothing_written(client, db, label, command):
    user = _make_user(db)
    _login(client)

    response = _create(client, label, command)

    assert response.status_code == 400, response.text
    body = response.json()
    assert body["ok"] is False
    assert body["error"]
    assert body["csrf_token"]
    assert _rows(db, user.id) == []


def test_an_emoji_sequence_is_not_a_control_character(client, db):
    """The ZWJ that joins a family emoji is category Cf, the variation selector Mn;
    a check by `isprintable()` or a blanket Cf ban would refuse both."""
    user = _make_user(db)
    _login(client)

    response = _create(client, "\U0001F468\u200D\U0001F469\u200D\U0001F467 \u2764\uFE0F", "stat")

    assert response.status_code == 201, response.text
    assert _rows(db, user.id)[0].label == "\U0001F468\u200D\U0001F469\u200D\U0001F467 \u2764\uFE0F"


def test_the_cap_refuses_instead_of_evicting(client, db, monkeypatch):
    monkeypatch.setattr(crud_favorite, "MAX_COMMAND_FAVORITES_PER_USER", 3)
    user = _make_user(db)
    _login(client)
    for n in range(3):
        assert _create(client, f"fav {n}", f"cmd {n}").status_code == 201

    response = _create(client, "one too many", "cmd 3")

    assert response.status_code == 409, response.text
    assert response.json()["ok"] is False
    assert "3" in response.json()["error"]
    assert [r.command for r in _rows(db, user.id)] == ["cmd 0", "cmd 1", "cmd 2"]


def test_a_position_after_a_single_row_at_zero_is_one(db):
    """coalesce(max, -1) + 1 — `max or -1` would read the 0 as missing."""
    user = _make_user(db)
    first = crud_favorite.create_favorite(db, user.id, "a", "a")
    second = crud_favorite.create_favorite(db, user.id, "b", "b")
    assert (first.position, second.position) == (0, 1)


# --- delete ------------------------------------------------------------------------------

def test_the_owner_can_delete(client, db):
    user = _make_user(db)
    _login(client)
    favorite_id = _create(client, "Status", "stat").json()["favorite"]["id"]

    response = _delete(client, favorite_id)

    assert response.status_code == 200, response.text
    assert response.json()["ok"] is True
    assert _rows(db, user.id) == []


def test_an_unknown_id_is_404(client, db):
    _make_user(db)
    _login(client)

    response = _delete(client, 424242)

    assert response.status_code == 404, response.text
    assert response.json()["ok"] is False


@pytest.mark.parametrize("favorite_id", [0, -1, 2**31, 2**70])
def test_an_id_outside_the_column_is_422_not_500(client, db, favorite_id):
    """sqlite3 raised OverflowError binding anything past 64 bits — a 500 with a
    traceback in the log, from an authenticated session, for a URL. The route
    bounds the id to the Integer column before any query is built."""
    user = _make_user(db)
    _login(client)
    kept = _create(client, "Status", "stat").json()["favorite"]["id"]

    response = _delete(client, favorite_id)

    assert response.status_code == 422, response.text
    assert "input" not in response.text, "the 422 handler must not echo the request"
    assert [r.id for r in _rows(db, user.id)] == [kept]


def test_another_users_favorite_is_404_and_untouched(client, db):
    alice = _make_user(db, "alice")
    _make_user(db, "bob")
    _login(client, "alice")
    favorite_id = _create(client, "Status", "stat").json()["favorite"]["id"]
    client.cookies.clear()
    _login(client, "bob")

    response = _delete(client, favorite_id)

    assert response.status_code == 404, response.text
    assert [r.id for r in _rows(db, alice.id)] == [favorite_id]


def test_an_administrator_has_no_way_around_ownership(client, db):
    alice = _make_user(db, "alice")
    _make_user(db, "admin", admin=True)
    _login(client, "alice")
    favorite_id = _create(client, "Status", "stat").json()["favorite"]["id"]
    client.cookies.clear()
    _login(client, "admin")

    response = _delete(client, favorite_id)

    assert response.status_code == 404, response.text
    assert [r.id for r in _rows(db, alice.id)] == [favorite_id]


# --- guards ------------------------------------------------------------------------------

def test_a_bad_csrf_token_is_refused_on_both_routes(client, db):
    user = _make_user(db)
    _login(client)
    favorite_id = _create(client, "Status", "stat").json()["favorite"]["id"]

    assert _create(client, "Wake", "wakeup", csrf="garbage").status_code == 403
    assert _delete(client, favorite_id, csrf="garbage").status_code == 403
    assert [r.id for r in _rows(db, user.id)] == [favorite_id]


def test_without_a_session_nothing_is_written(client, db):
    user = _make_user(db)

    response = client.post(
        "/terminal/favorites",
        data={"label": "Status", "command": "stat", "csrf_token": "x"},
        follow_redirects=False,
    )

    assert response.status_code in (302, 303, 307, 401, 403), response.text
    assert _rows(db, user.id) == []
