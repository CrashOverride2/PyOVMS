"""
Functional tests for POST /api/v1/auth/device-token.

This is an authentication endpoint, so import-level assertions are not enough — these
drive it over HTTP against a real (temporary SQLite) database.

The property under test throughout is that the new path is not *weaker* than the web
login it replaces. A second authentication route is the classic place for a guard to
go missing, so each check the UI performs has a test here.
"""

import datetime
import re
from pathlib import Path

import pyotp
import pytest
from fastapi.testclient import TestClient

from app import crud, security
from app.database import Base, SessionLocal, engine, get_db
from app.main import app
from app.models import db as models_db
from app.security_manager import security_manager

PASSWORD = "CorrectHorse1!Battery"
URL = "/api/v1/auth/device-token"
REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module", autouse=True)
def _schema():
    """
    Ensure the tables exist. Deliberately does NOT drop them afterwards: conftest
    already points the whole suite at a dedicated temporary SQLite file, and other
    modules start the app (which migrates) — dropping here pulled the schema out from
    under whichever module happened to run next.
    """
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
    """
    Each test starts from an empty user/key table and an unblocked rate limiter.

    The persisted rows matter as much as the in-memory state: every test here shares
    the client address "testclient". A leftover BlockedIP row turns every later
    request into a 429 from SecurityMiddleware before it reaches the endpoint, and
    leftover SecurityFailure rows feed record_failure()'s cumulative counter — which
    is read from the database, so it survives not just the test but the whole run and
    made the suite pass once and then fail on a second invocation.
    """
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
    """
    TestClient without the lifespan context.

    Deliberately not `with TestClient(app)`: that runs the real startup, which
    connects MQTT, downloads the disposable-email blocklist over the network and
    restores persisted IP blocks — none of which this endpoint needs, and the last of
    which would undo the rate-limiter reset above.
    """
    def _get_db():
        session = SessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = _get_db
    yield TestClient(app)
    app.dependency_overrides.clear()


def _make_user(db, username="alice", active=True, totp=False, admin=False):
    user = models_db.User(
        username=username,
        email=f"{username}@example.com",
        hashed_password=security.get_password_hash(PASSWORD),
        is_active=active,
        is_admin=admin,
        is_totp_enabled=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    secret = None
    if totp:
        secret = pyotp.random_base32()
        crud.user.enable_totp_for_user(db, user, secret)
        db.refresh(user)
    return user, secret


def _post(client, **overrides):
    body = {"username": "alice", "password": PASSWORD, "device_name": "ios-abc123"}
    body.update(overrides)
    return client.post(URL, json=body)


# --- the happy paths ------------------------------------------------------------------

def test_issues_a_key_for_valid_credentials(client, db):
    _make_user(db)

    response = _post(client)

    assert response.status_code == 201
    body = response.json()
    assert body["api_key"]
    assert body["key_prefix"] == body["api_key"][:8]
    # The broker credentials are the same secret today, but the app must not have to
    # know that — it reads these fields.
    assert body["mqtt_username"] == body["key_prefix"]
    assert body["mqtt_password"] == body["api_key"]

    # The key must actually authenticate.
    ping = client.get("/api/v1/auth/ping", headers={"X-API-Key": body["api_key"]})
    assert ping.status_code == 200


def test_issued_key_expires(client, db):
    _make_user(db)

    body = _post(client).json()

    assert body["expires_at"] is not None
    expires = datetime.datetime.fromisoformat(body["expires_at"])
    if expires.tzinfo is None:  # SQLite hands back naive datetimes
        expires = expires.replace(tzinfo=datetime.timezone.utc)
    remaining = expires - datetime.datetime.now(datetime.timezone.utc)
    assert 170 < remaining.days < 190, "device keys must not be indefinite"


def test_totp_account_succeeds_with_a_valid_code(client, db):
    _make_user(db, totp=True)
    _, secret = None, None
    user = db.query(models_db.User).filter_by(username="alice").first()
    secret = crud.user.get_decrypted_totp_secret_for_user(user)

    response = _post(client, totp_code=pyotp.TOTP(secret).now())

    assert response.status_code == 201
    assert response.json()["api_key"]


# --- 2FA must not be skippable ---------------------------------------------------------

def test_totp_account_without_a_code_is_told_to_ask_for_one(client, db):
    _make_user(db, totp=True)

    response = _post(client)

    assert response.status_code == 401
    assert response.json()["reason"] == "totp_required"


def test_totp_account_with_a_wrong_code_is_refused(client, db):
    _make_user(db, totp=True)

    response = _post(client, totp_code="000000")

    assert response.status_code == 401
    assert response.json()["reason"] == "totp_invalid"


def test_no_key_is_created_when_2fa_is_not_satisfied(client, db):
    """The regression that matters most: a key handed out before the second factor."""
    _make_user(db, totp=True)

    _post(client)
    _post(client, totp_code="000000")

    assert db.query(models_db.ApiKey).count() == 0


# --- credentials ------------------------------------------------------------------------

def test_wrong_password_is_refused(client, db):
    _make_user(db)

    response = _post(client, password="WrongPassword1!x")

    assert response.status_code == 401
    assert response.json()["reason"] == "invalid_credentials"


def test_unknown_user_and_wrong_password_are_indistinguishable(client, db):
    """Anything finer grained is an account enumeration oracle."""
    _make_user(db)

    unknown = _post(client, username="nosuchuser")
    wrong = _post(client, password="WrongPassword1!x")

    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json()


def test_inactive_account_is_refused_with_the_same_generic_error(client, db):
    _make_user(db, active=False)

    response = _post(client)
    reference = _post(client, username="nosuchuser")

    assert response.status_code == 401
    assert response.json() == reference.json(), "must not reveal that the account exists"
    assert db.query(models_db.ApiKey).count() == 0


# --- WebAuthn accounts must not be downgraded -------------------------------------------

def _add_webauthn(db, user, usage_mode):
    db.add(models_db.WebAuthnCredential(
        user_id=user.id, credential_id=f"cred-{usage_mode}-{user.id}".encode(),
        public_key=b"x", sign_count=0, is_active=True, usage_mode=usage_mode,
    ))
    db.commit()


def test_webauthn_2fa_account_is_sent_to_the_web_flow(client, db):
    """
    The UI offers *only* WebAuthn to these accounts. Accepting a TOTP code here would
    let password + TOTP bypass the stronger factor the account actually uses.
    """
    user, _ = _make_user(db, totp=True)
    _add_webauthn(db, user, "2fa")
    secret = crud.user.get_decrypted_totp_secret_for_user(
        db.query(models_db.User).filter_by(username="alice").first()
    )

    response = _post(client, totp_code=pyotp.TOTP(secret).now())

    assert response.status_code == 403
    assert response.json()["reason"] == "use_web_flow"
    assert db.query(models_db.ApiKey).count() == 0


def test_passwordless_only_account_cannot_use_password_login(client, db):
    user, _ = _make_user(db)
    _add_webauthn(db, user, "passwordless")

    response = _post(client)

    assert response.status_code == 403
    assert response.json()["reason"] == "use_web_flow"
    assert db.query(models_db.ApiKey).count() == 0


# --- re-provisioning and quota ----------------------------------------------------------

def test_reprovisioning_the_same_device_replaces_its_key(client, db):
    """
    The old flow left every previous key active, so repeated setup runs accumulated
    valid credentials the user could not see.
    """
    _make_user(db)

    first = _post(client).json()
    second = _post(client).json()

    assert first["api_key"] != second["api_key"]
    assert db.query(models_db.ApiKey).count() == 1

    # The superseded key must be dead.
    assert client.get("/api/v1/auth/ping",
                      headers={"X-API-Key": first["api_key"]}).status_code == 401
    assert client.get("/api/v1/auth/ping",
                      headers={"X-API-Key": second["api_key"]}).status_code == 200


def test_a_different_device_gets_its_own_key(client, db):
    _make_user(db)

    _post(client, device_name="ios-one")
    _post(client, device_name="android-two")

    assert db.query(models_db.ApiKey).count() == 2


def test_device_keys_count_against_the_user_quota(client, db):
    """
    A device key is user-requested, so it must not take the internal exemption — that
    exemption is what finding N-3 was about.
    """
    from app.config import settings

    _make_user(db)
    original = settings.MAX_API_KEYS_PER_USER
    settings.MAX_API_KEYS_PER_USER = 2
    try:
        assert _post(client, device_name="d1").status_code == 201
        assert _post(client, device_name="d2").status_code == 201
        blocked = _post(client, device_name="d3")
        assert blocked.status_code == 403
        assert blocked.json()["reason"] == "quota_exceeded"
    finally:
        settings.MAX_API_KEYS_PER_USER = original


# --- input validation --------------------------------------------------------------------

@pytest.mark.parametrize("device_name", [
    "bad/name", "semi;colon", "new\nline", "quote\"mark", "",
])
def test_device_name_is_restricted(client, db, device_name):
    _make_user(db)

    response = _post(client, device_name=device_name)

    assert response.status_code == 422


def test_device_name_cannot_impersonate_an_internal_key(client, db):
    """
    Reserved prefixes are rejected by the CRUD guard; the device prefix keeps these
    names in their own namespace regardless.
    """
    _make_user(db)

    response = _post(client, device_name="ws-ticket-mallory")

    assert response.status_code == 201
    key = db.query(models_db.ApiKey).first()
    assert key.name.startswith("device-")
    assert not key.name.startswith("ws-ticket-")


# --- the expiry slides, so a working install never breaks -----------------------------------

def test_the_device_prefix_is_reserved_from_user_input():
    """
    What makes the name a trustworthy marker for the sliding expiry below. Without
    this a user could name a key "device-x" from the profile page and opt it into
    an expiry that renews itself.
    """
    from app.crud import apikey

    assert apikey.is_reserved_key_name("device-my-phone")

    from pydantic import ValidationError

    from app.models import api as models_api
    with pytest.raises(ValidationError):
        models_api.ApiKeyCreate(name="device-my-phone")


def test_using_a_device_key_pushes_its_expiry_out(client, db):
    """
    The property that makes "set it up once" work: the key expires 180 days after it
    was last used, not after it was issued.
    """
    _make_user(db)
    key_value = _post(client).json()["api_key"]

    stored = db.query(models_db.ApiKey).first()
    stored.expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3)
    db.commit()

    assert client.get("/api/v1/auth/ping",
                      headers={"X-API-Key": key_value}).status_code == 200

    db.expire_all()
    refreshed = db.query(models_db.ApiKey).first()
    expires = refreshed.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=datetime.timezone.utc)
    remaining = expires - datetime.datetime.now(datetime.timezone.utc)
    assert remaining.days > 170, "using the key must renew it"


def test_a_pre_existing_key_named_like_a_device_never_slides(db):
    """
    Migration safety, and the reason is_device_key is a column rather than a name
    check. `device-` only became reserved on 2026-08-02, so a user may already have a
    key called "device-tesla" with a deliberately short expiry. Inferring the marker
    from the name would have quietly pushed that expiry from 30 days to 180 on every
    request — the opposite of what they configured.
    """
    from app.crud import apikey

    user, _ = _make_user(db)
    legacy = models_db.ApiKey(
        key_prefix="legacy01", hashed_key="h" * 64, user_id=user.id,
        name="device-tesla", is_active=True,
        created_at=datetime.datetime.now(datetime.timezone.utc),
        expires_at=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30),
        is_device_key=False,   # what the migration leaves on every existing row
    )
    db.add(legacy)
    db.commit()
    db.refresh(legacy)
    original = legacy.expires_at

    assert apikey.is_device_key(legacy) is False, "the name must not decide this"
    assert apikey.slide_device_key_expiry(legacy) is False
    assert legacy.expires_at == original


def test_a_provisioned_device_key_carries_the_marker(client, db):
    """The other half: keys from the endpoint must actually be flagged, or they expire hard."""
    _make_user(db)
    _post(client)

    stored = db.query(models_db.ApiKey).first()
    assert stored.is_device_key is True


def test_a_user_created_key_expiry_is_never_extended(db):
    """
    An expiry someone typed into the profile page is a deliberate statement and must
    be honoured literally — only device keys slide.
    """
    from app.crud import apikey

    user, _ = _make_user(db)
    key, _plain = apikey.create_api_key(
        db, user_id=user.id, name="my laptop",
        expires_delta=datetime.timedelta(days=3),
    )
    original = key.expires_at

    changed = apikey.slide_device_key_expiry(key)

    assert changed is False
    assert key.expires_at == original


def test_a_key_without_an_expiry_does_not_gain_one(db):
    from app.crud import apikey

    user, _ = _make_user(db)
    key, _plain = apikey.create_api_key(db, user_id=user.id, name="device-legacy",
                                        purpose=apikey.KeyPurpose.DEVICE)
    assert key.expires_at is None

    assert apikey.slide_device_key_expiry(key) is False
    assert key.expires_at is None


def test_an_expired_key_does_not_lock_the_client_out(client, db):
    """
    A lapsed key is not evidence of guessing — the caller demonstrably held a real
    one. Counting it meant an app still polling in the background blocked its own
    address after ten tries, and the user could then not even reach the login page
    to re-provision.
    """
    _make_user(db)
    key_value = _post(client).json()["api_key"]

    stored = db.query(models_db.ApiKey).first()
    stored.expires_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1)
    db.commit()

    for _ in range(15):
        assert client.get("/api/v1/auth/ping",
                          headers={"X-API-Key": key_value}).status_code == 401

    assert not security_manager.is_blocked("testclient"), (
        "retrying with a lapsed key must not block the user's own address"
    )


def test_an_unknown_key_is_still_counted_as_a_guess(client, db):
    """The relaxation above must not extend to keys that were never issued."""
    _make_user(db)

    for _ in range(15):
        client.get("/api/v1/auth/ping", headers={"X-API-Key": "not-a-real-key-at-all"})

    assert security_manager.is_blocked("testclient")


# --- what the user sees, and what counts against them ---------------------------------------

def test_the_device_key_is_visible_in_the_key_list(client, db):
    """
    A device key is a phone the user set up. Seeing it — and being able to revoke it —
    is the point of that list, so it must not be hidden like server plumbing.
    """
    user, _ = _make_user(db)
    _post(client, device_name="ios-abc")

    listed = crud.apikey.get_api_keys_for_user(db, user_id=user.id)

    assert [k.name for k in listed] == ["device-ios-abc"]


def test_the_device_key_is_returned_by_the_api_listing(client, db):
    _make_user(db)
    key = _post(client).json()["api_key"]

    response = client.get("/api/v1/apikeys", headers={"X-API-Key": key})

    assert response.status_code == 200
    assert any(item["name"].startswith("device-") for item in response.json())


def test_websocket_tickets_are_hidden_from_the_user(db):
    """
    Tickets are minted every time a page opens a socket and only removed once that
    socket connects, so an abandoned page left rows in the user's key list until
    hourly housekeeping. There is nothing the user can do with them.
    """
    user, _ = _make_user(db)
    crud.apikey.create_api_key(
        db, user_id=user.id, name="ws-ticket-alice-123.45",
        expires_delta=datetime.timedelta(minutes=1),
        purpose=crud.apikey.KeyPurpose.INTERNAL,
    )
    crud.apikey.create_api_key(db, user_id=user.id, name="my laptop")

    visible = crud.apikey.get_api_keys_for_user(db, user_id=user.id)
    everything = crud.apikey.get_api_keys_for_user(db, user_id=user.id, include_internal=True)

    assert [k.name for k in visible] == ["my laptop"]
    assert len(everything) == 2, "the rows still exist, they are only hidden"


def test_internal_keys_do_not_consume_the_user_quota(db):
    """
    The exemption used to be one-sided: creating a ticket skipped the quota check, but
    the ticket then occupied a slot for real keys until it was swept.
    """
    from app.config import settings

    user, _ = _make_user(db)
    for i in range(5):
        crud.apikey.create_api_key(
            db, user_id=user.id, name=f"ws-ticket-alice-{i}",
            expires_delta=datetime.timedelta(minutes=1),
            purpose=crud.apikey.KeyPurpose.INTERNAL,
        )

    original = settings.MAX_API_KEYS_PER_USER
    settings.MAX_API_KEYS_PER_USER = 2
    try:
        crud.apikey.create_api_key(db, user_id=user.id, name="real one")
        crud.apikey.create_api_key(db, user_id=user.id, name="real two")
        with pytest.raises(ValueError, match="limit reached"):
            crud.apikey.create_api_key(db, user_id=user.id, name="real three")
    finally:
        settings.MAX_API_KEYS_PER_USER = original


def test_both_internal_prefixes_are_still_in_use():
    """
    Guard against dead machinery: if either of these stops being used, the prefix and
    its special-casing should go too rather than linger as unexplained surface.
    """
    ws_ticket_users = (REPO_ROOT / "app" / "templates" / "admin_logs.html").read_text()
    assert "api_get_ws_ticket" in ws_ticket_users, "WebSocket tickets serve the live log view"

    vehicle_service = (REPO_ROOT / "app" / "services" / "vehicle_service.py").read_text()
    assert "temp-karto-delete-" in vehicle_service, "Karto deletion still mints a temp key"
    assert "delete_api_key_by_id_and_user" in vehicle_service, (
        "the Karto temp key must be cleaned up in a finally block, not left to housekeeping"
    )


# --- rate limiting ------------------------------------------------------------------------

def test_repeated_failures_eventually_block_the_address(client, db):
    """
    Failed provisioning must feed the same limiter as a failed web login — otherwise
    this endpoint is an unmetered password oracle standing next to a metered one.
    """
    _make_user(db)

    for _ in range(6):
        _post(client, password="WrongPassword1!x")

    assert security_manager.is_blocked("testclient")


def test_a_blocked_ip_is_turned_away_before_any_credential_check(client, db, monkeypatch):
    """
    SecurityMiddleware rejects the request before routing, so the response is its
    generic 429 rather than this endpoint's structured error. The check inside the
    endpoint is the second layer and is asserted by not issuing a key.
    """
    _make_user(db)
    monkeypatch.setattr(security_manager, "is_blocked", lambda ip: True)

    response = _post(client)

    assert response.status_code == 429
    assert db.query(models_db.ApiKey).count() == 0


def test_missing_totp_code_does_not_burn_the_rate_limit_budget(client, db):
    """
    Opening the 2FA dialog is not a failed attempt. Counting it would let the app's
    normal two-step flow lock the user out.
    """
    _make_user(db, totp=True)
    before = sum(
        len(per_type.get("totp", []))
        for per_type in security_manager.failed_attempts.values()
    )

    _post(client)

    after = sum(
        len(per_type.get("totp", []))
        for per_type in security_manager.failed_attempts.values()
    )
    assert after == before


# --- POST /api/v1/auth/device-token/from-session ---------------------------------------
#
# The counterpart for the logins that cannot be carried over a single JSON request.
# An account whose second factor is a security key is refused by /device-token on
# purpose, so the app completes the interactive web login and calls this instead.
#
# Before it existed, that fallback ended in POST /profile/apikeys/create and the app
# ran on a plain *user* key: no expiry, and untouched by the revocation a password
# change or reset performs on device keys. The accounts with the strongest second
# factor therefore held the weakest credential. What these tests pin is that both
# provisioning routes produce the *same kind* of credential.

SESSION_URL = "/api/v1/auth/device-token/from-session"


@pytest.fixture
def session_client():
    """
    A client that can hold a session cookie.

    base_url is https on purpose: FORCE_SECURE_COOKIES defaults to True, so
    SessionMiddleware marks the cookie Secure and an http client stores it but never
    sends it back — the login then fails with "CSRF token missing from session" and
    the cause is entirely invisible in the response. This mirrors a real deployment,
    which is behind TLS anyway.
    """
    def _get_db():
        session = SessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = _get_db
    yield TestClient(app, base_url="https://testserver")
    app.dependency_overrides.clear()


def _login_session(client, db, username="alice", password=PASSWORD):
    """Log in through the real UI route so the session is exactly what a browser holds."""
    page = client.get("/login")
    token = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page.text)
    if token is None:
        token = re.search(r'value="([^"]+)"[^>]*name="csrf_token"', page.text)
    response = client.post(
        "/login",
        data={"username": username, "password": password, "csrf_token": token.group(1)},
        follow_redirects=False,
    )
    return response


def _session_csrf(client):
    return client.get("/profile/csrf-token").json()["csrf_token"]


def test_session_route_issues_a_device_key(session_client, db):
    _make_user(db)
    _login_session(session_client, db)

    response = session_client.post(SESSION_URL,
                           json={"device_name": "ios-abc123", "csrf_token": _session_csrf(session_client)})

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["api_key"] and body["mqtt_password"] == body["api_key"]
    assert body["mqtt_username"] == body["key_prefix"]


def test_session_route_produces_the_same_kind_of_key_as_the_password_route(session_client, db):
    """
    The whole point. A key from here must be a DEVICE key: server-chosen name, sliding
    expiry, and — the part that matters — revoked when the password changes.
    """
    _make_user(db)
    _login_session(session_client, db)
    session_client.post(SESSION_URL,
                json={"device_name": "ios-abc123", "csrf_token": _session_csrf(session_client)})

    key = db.query(models_db.ApiKey).filter(
        models_db.ApiKey.name == "device-ios-abc123"
    ).one()
    assert key.is_device_key is True
    assert key.expires_at is not None


def test_key_from_the_session_route_is_revoked_by_a_password_change(session_client, db):
    """
    The property the web-flow fallback did not have. Verified through the revocation
    path itself rather than by asserting on the flag, because the flag is only a means.
    """
    user, _ = _make_user(db)
    _login_session(session_client, db)
    body = session_client.post(SESSION_URL,
                       json={"device_name": "ios-abc123", "csrf_token": _session_csrf(session_client)}).json()

    ping = session_client.get("/api/v1/auth/ping", headers={"X-API-Key": body["api_key"]})
    assert ping.status_code == 200

    from app.models import api as models_api
    crud.user.update_user(db, user, models_api.UserUpdate(password="BrandNew1!Password"))

    ping = session_client.get("/api/v1/auth/ping", headers={"X-API-Key": body["api_key"]})
    assert ping.status_code == 401


def test_session_route_replaces_the_previous_key_for_the_same_device(session_client, db):
    _make_user(db)
    _login_session(session_client, db)
    first = session_client.post(SESSION_URL,
                        json={"device_name": "ios-abc123", "csrf_token": _session_csrf(session_client)}).json()
    second = session_client.post(SESSION_URL,
                         json={"device_name": "ios-abc123", "csrf_token": _session_csrf(session_client)}).json()

    assert first["api_key"] != second["api_key"]
    assert session_client.get("/api/v1/auth/ping",
                      headers={"X-API-Key": first["api_key"]}).status_code == 401
    assert session_client.get("/api/v1/auth/ping",
                      headers={"X-API-Key": second["api_key"]}).status_code == 200


def test_session_route_needs_a_session(session_client, db):
    _make_user(db)

    response = session_client.post(SESSION_URL,
                                   json={"device_name": "ios-abc123", "csrf_token": "anything"})

    assert response.status_code == 401
    assert response.json()["reason"] == "not_authenticated"


def test_session_route_needs_a_csrf_token(session_client, db):
    """
    This route carries ambient authority, unlike its sibling. Without the check any
    page could mint a device key — and therefore an MQTT password — for a visitor.
    """
    _make_user(db)
    _login_session(session_client, db)

    response = session_client.post(SESSION_URL,
                           json={"device_name": "ios-abc123", "csrf_token": "not-the-right-token"})

    assert response.status_code == 403
    assert response.json()["reason"] == "csrf_invalid"
    assert db.query(models_db.ApiKey).count() == 0


def test_session_route_requires_recent_authentication(session_client, db, monkeypatch):
    """
    Same gate as POST /profile/apikeys/create. A session that has been sitting open is
    not enough to mint a credential that doubles as the MQTT password.
    """
    _make_user(db)
    _login_session(session_client, db)
    csrf = _session_csrf(session_client)

    # Age the marker out by shrinking the window rather than by moving the clock: the
    # module reads the constant on every call, and patching the global time.time()
    # would reach far beyond the request under test.
    from app.utils import step_up
    monkeypatch.setattr(step_up, "STEP_UP_WINDOW_SECONDS", -1)

    response = session_client.post(SESSION_URL,
                                   json={"device_name": "ios-abc123", "csrf_token": csrf})

    assert response.status_code == 403
    assert response.json()["reason"] == "reauth_required"
    assert db.query(models_db.ApiKey).count() == 0


def test_session_route_rejects_a_reserved_device_name(session_client, db):
    _make_user(db)
    _login_session(session_client, db)

    response = session_client.post(SESSION_URL,
                           json={"device_name": "ios/../../etc", "csrf_token": _session_csrf(session_client)})

    assert response.status_code == 422


def test_both_routes_mint_through_the_same_helper():
    """
    Two ways in must not drift into two kinds of credential — that drift is exactly
    what this endpoint was added to remove.
    """
    import inspect

    from app.routers.api import device_auth

    for route in (device_auth.create_device_token, device_auth.create_device_token_from_session):
        assert "_issue_device_key(" in inspect.getsource(route)
