"""
Deleting an account deletes its command favorites — on every path.

Same shape as tests/test_config_backup_account_deletion.py, for the same reason:
the rows leave through the ORM cascade on `User.command_favorites`, because SQLite
does not enforce the column's `ON DELETE CASCADE` (see the PRAGMA note in
app/database.py). All four ways an account goes end in `crud.user.delete_user()`;
each is driven here in full, with another user's rows alongside to prove the
deletion stops at the account boundary.
"""

import re

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app import crud, security
from app.crud import command_favorite as crud_favorite
from app.database import Base, SessionLocal, engine, get_db
from app.main import app
from app.models import db as models_db
from app.security_manager import security_manager

PASSWORD = "CorrectHorse1!Battery"


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
    the client would drop it and every cookie-authenticated request would fail."""
    def _get_db():
        session = SessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = _get_db
    yield TestClient(app, base_url="https://testserver")
    app.dependency_overrides.clear()


def _make_user(db, username, *, admin=False):
    user = models_db.User(
        username=username, email=f"{username}@example.com",
        hashed_password=security.get_password_hash(PASSWORD),
        is_active=True, is_admin=admin, is_totp_enabled=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _fill(db, user):
    for n in range(3):
        crud_favorite.create_favorite(db, user.id, f"fav {n}", f"cmd {n}")


def _favorites_of(db, user_id) -> int:
    return db.query(models_db.CommandFavorite).filter_by(owner_id=user_id).count()


def _login(client, username):
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


@pytest.fixture
def doomed_and_bystander(db):
    """Two accounts with favorites, as ids — the doomed instance itself is unusable
    once its row is gone. `bystander` must come out untouched."""
    doomed = _make_user(db, "doomed")
    bystander = _make_user(db, "bystander")
    _fill(db, doomed)
    _fill(db, bystander)
    assert _favorites_of(db, doomed.id) == 3
    assert _favorites_of(db, bystander.id) == 3
    return doomed.id, bystander.id


def _assert_only_the_bystander_remains(db, doomed_id, bystander_id):
    db.expire_all()
    assert db.query(models_db.User).filter_by(id=doomed_id).first() is None
    assert _favorites_of(db, doomed_id) == 0, "the account's favorites outlived it"
    assert _favorites_of(db, bystander_id) == 3, "another user's favorites were touched"


# --- the four paths -------------------------------------------------------------------

def test_an_administrator_deleting_over_the_api_takes_the_favorites(client, db, doomed_and_bystander):
    doomed_id, bystander_id = doomed_and_bystander
    admin = _make_user(db, "admin", admin=True)
    _, key = crud.apikey.create_api_key(db=db, user_id=admin.id, name="admin-key")

    response = client.delete(f"/api/v1/users/{doomed_id}", headers={"X-API-Key": key})

    assert response.status_code == 200, response.text
    _assert_only_the_bystander_remains(db, doomed_id, bystander_id)


def test_an_administrator_deleting_on_the_users_page_takes_the_favorites(client, db, doomed_and_bystander):
    doomed_id, bystander_id = doomed_and_bystander
    _make_user(db, "admin", admin=True)
    _login(client, "admin")

    response = client.post(
        f"/users/{doomed_id}/delete",
        data={"csrf_token": _session_csrf(client)}, follow_redirects=False,
    )

    assert response.status_code == 303, response.text
    assert "error_message" not in response.headers["location"], response.headers["location"]
    _assert_only_the_bystander_remains(db, doomed_id, bystander_id)


def test_a_user_deleting_their_own_account_takes_the_favorites(client, db, doomed_and_bystander):
    """Login counts as recent re-authentication, so the step-up gate lets the
    request through; the confirmation word is what the form requires."""
    doomed_id, bystander_id = doomed_and_bystander
    _login(client, "doomed")

    response = client.post(
        "/profile/delete",
        data={"delete_confirmation": "DELETE", "csrf_token": _session_csrf(client)},
        follow_redirects=False,
    )

    assert response.status_code == 303, response.text
    assert "/login" in response.headers["location"], response.headers["location"]
    _assert_only_the_bystander_remains(db, doomed_id, bystander_id)


def test_the_lifecycle_housekeeping_path_takes_the_favorites(db, doomed_and_bystander):
    """periodic_lifecycle_housekeeping ends in the same call; there is no HTTP."""
    doomed_id, bystander_id = doomed_and_bystander

    assert crud.user.delete_user(db, doomed_id) is not None

    _assert_only_the_bystander_remains(db, doomed_id, bystander_id)


# --- and on a backend that enforces foreign keys ----------------------------------------

def test_the_constraint_cascades_where_the_database_enforces_it():
    """PostgreSQL and MySQL enforce the column's ON DELETE. It must be CASCADE, not
    RESTRICT: a `security_events`-style violation here would make every account
    with a favorite impossible to delete on those backends."""
    fk_engine = create_engine("sqlite://", connect_args={"check_same_thread": False})

    @event.listens_for(fk_engine, "connect")
    def _enforce_fks(dbapi_connection, _record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(fk_engine)
    session = sessionmaker(bind=fk_engine)()
    try:
        user = models_db.User(username="doomed", email="doomed@example.com",
                              hashed_password="x", is_active=True)
        session.add(user)
        session.commit()
        _fill(session, user)
        assert _favorites_of(session, user.id) == 3

        # Straight SQL, past the ORM cascade: only the constraint is at work here.
        session.execute(models_db.User.__table__.delete().where(models_db.User.id == user.id))
        session.commit()

        assert session.query(models_db.CommandFavorite).count() == 0
    finally:
        session.close()
        fk_engine.dispose()

    fk = next(fk for fk in models_db.CommandFavorite.__table__.foreign_keys if fk.column.table.name == "users")
    assert fk.ondelete == "CASCADE"
