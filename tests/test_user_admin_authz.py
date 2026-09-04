"""
Functional guards for /api/v1/users — the administrative user surface.

Two properties, both of which were once only true by inspection:

  * **Nobody but an admin reaches it.** The guard is a router-level dependency, so it
    is not visible in any route's signature: reading create_user_api() alone shows a
    handler that accepts `is_admin: true` and writes it straight to the database.
    That is what this file exists to disprove, over HTTP, for every verb.
  * **A privilege change is recorded.** Granting admin used to leave an audit trail
    identical to a name correction, which is what makes a second admin account the
    natural persistence mechanism for a stolen admin key.

The last-admin invariant is the third. It is *currently* unreachable through these
routes — the actor is always an active admin and cannot demote, deactivate or delete
themselves — but that safety is an emergent property of three separate self-checks in
two routers, not something anything asserts. These tests pin the invariant itself.
"""

import pytest
from fastapi.testclient import TestClient

from app import crud, security
from app.database import Base, SessionLocal, engine, get_db
from app.main import app
from app.models import db as models_db
from app.security_events import SecurityEventType
from app.security_manager import security_manager

PASSWORD = "CorrectHorse1!Battery"
URL = "/api/v1/users"

# A payload that would create a second administrator if the guard were missing.
ESCALATION = {
    "username": "backdoor",
    "email": "backdoor@example.com",
    "password": "An0ther!Str0ngPass",
    "is_admin": True,
}


@pytest.fixture(scope="module", autouse=True)
def _schema():
    """See tests/test_device_token_endpoint.py — the schema is shared, never dropped."""
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
    """TestClient without lifespan — see test_device_token_endpoint.py for why."""
    def _get_db():
        session = SessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = _get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


def _make_user(db, username, *, admin=False, active=True):
    user = models_db.User(
        username=username,
        email=f"{username}@example.com",
        hashed_password=security.get_password_hash(PASSWORD),
        is_active=active,
        is_admin=admin,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _key_for(db, user):
    _, plain = crud.apikey.create_api_key(db=db, user_id=user.id, name="test")
    return plain


def _events(db, event_type):
    return (
        db.query(models_db.SecurityEvent)
        .filter(models_db.SecurityEvent.event_type == event_type.value)
        .all()
    )


# --- who reaches the endpoint ---------------------------------------------------------

@pytest.mark.parametrize(
    "method,path",
    [
        ("post", URL),
        ("get", URL),
        ("get", f"{URL}/1"),
        ("put", f"{URL}/1"),
        ("delete", f"{URL}/1"),
    ],
)
def test_every_verb_rejects_an_anonymous_caller(client, method, path):
    # client.request(), not client.get()/delete(): httpx refuses a body on those.
    response = client.request(method, path, json=ESCALATION)
    assert response.status_code == 401, (
        f"{method.upper()} {path} answered {response.status_code} without a key. The "
        "admin guard is a router-level dependency (api/users.py) — if it was moved or "
        "the route was added to me_router, it is gone."
    )


@pytest.mark.parametrize(
    "method,path",
    [
        ("post", URL),
        ("get", URL),
        ("get", f"{URL}/1"),
        ("put", f"{URL}/1"),
        ("delete", f"{URL}/1"),
    ],
)
def test_every_verb_rejects_a_non_admin_key(client, db, method, path):
    key = _key_for(db, _make_user(db, "bob"))

    response = client.request(method, path, json=ESCALATION, headers={"X-API-Key": key})

    assert response.status_code == 403, f"{method.upper()} {path} answered {response.status_code}"


def test_a_non_admin_cannot_create_an_admin(client, db):
    """The headline claim, stated as state rather than status code."""
    key = _key_for(db, _make_user(db, "bob"))

    assert client.post(URL, json=ESCALATION, headers={"X-API-Key": key}).status_code == 403
    assert crud.user.get_user_by_username(db, "backdoor") is None


def test_a_deactivated_admins_key_is_refused(client, db):
    """is_admin alone is not enough — the account has to still be usable."""
    key = _key_for(db, _make_user(db, "root", admin=True, active=False))

    assert client.post(URL, json=ESCALATION, headers={"X-API-Key": key}).status_code == 403


def test_the_self_service_router_does_not_widen_the_prefix(client):
    """
    me_router shares the /users prefix but not the admin guard, so its floor is its own
    router-level dependency. Without one, a route added there is unauthenticated while
    looking administrative.
    """
    response = client.put(f"{URL}/me/password", json={"current_password": "x", "new_password": "y"})
    assert response.status_code == 401


# --- the audit trail ------------------------------------------------------------------

def test_creating_an_admin_is_recorded(client, db):
    key = _key_for(db, _make_user(db, "root", admin=True))

    assert client.post(URL, json=ESCALATION, headers={"X-API-Key": key}).status_code == 201

    granted = _events(db, SecurityEventType.ADMIN_GRANTED)
    assert len(granted) == 1, "Creating an admin left no ADMIN_GRANTED event"
    assert granted[0].username == "backdoor"
    assert granted[0].details["changed_by"] == "root"
    assert granted[0].severity == "warning"


def test_creating_an_ordinary_user_is_not_recorded_as_a_grant(client, db):
    key = _key_for(db, _make_user(db, "root", admin=True))
    payload = {**ESCALATION, "is_admin": False}

    assert client.post(URL, json=payload, headers={"X-API-Key": key}).status_code == 201

    assert _events(db, SecurityEventType.ADMIN_GRANTED) == []


def test_promoting_an_existing_user_is_recorded(client, db):
    admin = _make_user(db, "root", admin=True)
    victim = _make_user(db, "bob")
    key = _key_for(db, admin)

    response = client.put(f"{URL}/{victim.id}", json={"is_admin": True}, headers={"X-API-Key": key})

    assert response.status_code == 200
    granted = _events(db, SecurityEventType.ADMIN_GRANTED)
    assert len(granted) == 1, "Promotion to admin left no ADMIN_GRANTED event"
    assert granted[0].details["via"] == "api_update"


def test_demoting_an_admin_is_recorded(client, db):
    admin = _make_user(db, "root", admin=True)
    other = _make_user(db, "second", admin=True)
    key = _key_for(db, admin)

    response = client.put(f"{URL}/{other.id}", json={"is_admin": False}, headers={"X-API-Key": key})

    assert response.status_code == 200
    assert len(_events(db, SecurityEventType.ADMIN_REVOKED)) == 1


def test_an_unrelated_edit_records_no_role_change(client, db):
    admin = _make_user(db, "root", admin=True)
    bob = _make_user(db, "bob")
    key = _key_for(db, admin)

    response = client.put(f"{URL}/{bob.id}", json={"full_name": "Bob B"}, headers={"X-API-Key": key})

    assert response.status_code == 200
    assert _events(db, SecurityEventType.ADMIN_GRANTED) == []
    assert _events(db, SecurityEventType.ADMIN_REVOKED) == []


# --- the last-admin invariant ----------------------------------------------------------

@pytest.mark.parametrize("payload", [{"is_admin": False}, {"is_active": False}])
def test_the_only_admin_cannot_be_demoted_or_deactivated(client, db, payload):
    """
    The invariant is checked ahead of the "you cannot edit yourself" rules, so this is
    the message the operator gets — the accurate one. Behind them the check would never
    execute at all, since a sole admin is necessarily the actor.
    """
    root = _make_user(db, "root", admin=True)
    key = _key_for(db, root)

    response = client.put(f"{URL}/{root.id}", json=payload, headers={"X-API-Key": key})

    assert response.status_code == 400
    assert "last remaining admin" in response.json()["detail"]
    db.refresh(root)
    assert root.is_admin is True
    assert root.is_active is True


def test_the_self_edit_rules_still_apply_when_another_admin_exists(client, db):
    """The invariant moving to the front must not swallow the self-checks behind it."""
    root = _make_user(db, "root", admin=True)
    _make_user(db, "second", admin=True)
    key = _key_for(db, root)

    response = client.put(f"{URL}/{root.id}", json={"is_admin": False}, headers={"X-API-Key": key})

    assert response.status_code == 400
    assert "own admin status" in response.json()["detail"]


def test_is_last_active_admin_ignores_inactive_and_non_admin_peers(db):
    """
    The invariant is about accounts that can still *log in and administer*. A
    deactivated admin is not a way back in, and neither is an active ordinary user —
    counting either would let the real last admin be removed.
    """
    root = _make_user(db, "root", admin=True)
    _make_user(db, "sleeping", admin=True, active=False)
    _make_user(db, "bob")

    assert crud.user.is_last_active_admin(db, root) is True

    second = _make_user(db, "second", admin=True)
    assert crud.user.is_last_active_admin(db, root) is False
    assert crud.user.is_last_active_admin(db, second) is False


def test_a_non_admin_is_never_the_last_admin(db):
    bob = _make_user(db, "bob")
    _make_user(db, "root", admin=True)

    assert crud.user.is_last_active_admin(db, bob) is False


def test_the_only_admin_cannot_be_deleted(client, db):
    """
    Deleting the sole admin is refused before Karto is contacted at all — the account
    must survive, not be half-removed.
    """
    root = _make_user(db, "root", admin=True)
    key = _key_for(db, root)

    response = client.delete(f"{URL}/{root.id}", headers={"X-API-Key": key})

    assert response.status_code == 400
    assert "last remaining admin" in response.json()["detail"]
    assert crud.user.get_user_by_id(db, root.id) is not None
