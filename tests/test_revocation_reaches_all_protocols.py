"""
Revocation must reach every protocol, not just the HTTP layer.

The second follow-up audit (doc/security-audit-2026-08-02-nachpruefung-2.md) found the
same mistake in two places: an operator deactivates an account, or a user resets their
password, the action reports success — and the intruder keeps working, because the
guard only ever lived in the FastAPI dependencies.

N-7  is_active was checked in the HTTP dependencies only. MQTT and V2 TCP never
     looked at it, so a disabled account kept receiving live telemetry and kept being
     allowed to publish commands to its vehicles.
N-8  A password reset bumped token_version (killing JWT sessions) but left API keys
     alone. Since round 5 the app's device key IS an API key, and it slides its own
     expiry forward on every use — so an attacker who had provisioned one kept
     indefinite access through the exact action taken to lock them out.
N-9  Per-account brute-force blocking applied to 'login' only. TOTP guesses were
     limited per IP, which a proxy pool defeats against a 10^6 keyspace.

These are written against the observable artefact — the generated ACL, the rows left
in the database, the block decision — rather than against the shape of the code, so a
future refactor that keeps the property keeps passing. Each one was checked against
the unpatched code and fails there; a test that cannot fail is what let H-4 regress
silently the first time round.
"""


import pytest

from app import crud, security
from app.crud import apikey as crud_apikey
from app.database import Base, SessionLocal, engine
from app.models import db as models_db
from app.security_manager import security_manager
from app.services.mqtt_auth_manager import MosquittoAuthManager

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
    db.query(models_db.ApiKey).delete()
    db.query(models_db.Vehicle).delete()
    db.query(models_db.User).delete()
    db.query(models_db.BlockedIP).delete()
    db.query(models_db.SecurityFailure).delete()
    db.commit()
    security_manager.blocked_ips.clear()
    security_manager.failed_attempts.clear()
    security_manager._blocked_usernames.clear()
    security_manager._username_failures.clear()
    yield


def _user(db, username="mallory", active=True):
    user = models_db.User(
        username=username,
        email=f"{username}@example.com",
        hashed_password=security.get_password_hash(PASSWORD),
        is_active=active,
        is_admin=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _vehicle(db, user, vehicle_id="CAR1"):
    vehicle = models_db.Vehicle(
        vehicle_id=vehicle_id,
        owner_id=user.id,
        protocol="v3",
        encrypted_server_password=b"placeholder",
    )
    db.add(vehicle)
    db.commit()
    return vehicle


def _api_key(db, user, prefix="abcd1234", device=False):
    key = models_db.ApiKey(
        key_prefix=prefix,
        hashed_key=f"hash-{prefix}",
        user_id=user.id,
        name=("device-phone" if device else "scripting"),
        is_active=True,
        is_device_key=device,
    )
    db.add(key)
    db.commit()
    db.refresh(key)
    return key


def _acl_for(db, tmp_path):
    """Generate the Mosquitto ACL exactly as the server does and return its text."""
    manager = MosquittoAuthManager(
        passwd_path=str(tmp_path / "passwd"), acl_path=str(tmp_path / "acl")
    )
    assert manager.regenerate_acl_file(db), "ACL generation failed"
    return (tmp_path / "acl").read_text()


# ---------------------------------------------------------------------------
# N-7 — deactivation must reach MQTT and V2 TCP
# ---------------------------------------------------------------------------


def test_active_owner_is_granted_mqtt_access(db, tmp_path):
    """Baseline. Without this the next test could pass by generating an empty ACL."""
    user = _user(db)
    _vehicle(db, user)
    _api_key(db, user)

    acl = _acl_for(db, tmp_path)

    assert "user CAR1" in acl
    assert "user abcd1234" in acl
    assert "topic readwrite ovms/mallory/CAR1/#" in acl


def test_deactivated_owner_loses_vehicle_mqtt_account(db, tmp_path):
    user = _user(db)
    _vehicle(db, user)
    _api_key(db, user)

    user.is_active = False
    db.commit()

    acl = _acl_for(db, tmp_path)

    assert "user CAR1" not in acl, "deactivated owner's vehicle still has a broker account"


def test_deactivated_owner_loses_api_key_topic_rules(db, tmp_path):
    """
    The API key account may still exist in the password file — its Mosquitto hash
    cannot be re-derived, so removing it would make deactivation irreversible. What
    must be gone is every topic rule, since Mosquitto denies by default.
    """
    user = _user(db)
    _vehicle(db, user)
    _api_key(db, user)

    user.is_active = False
    db.commit()

    acl = _acl_for(db, tmp_path)

    assert "topic readwrite ovms/mallory/CAR1/#" not in acl
    assert "ovms/mallory" not in acl, "deactivated account retains topic access"


def test_reactivating_an_owner_restores_mqtt_access(db, tmp_path):
    """Deactivation must be reversible, or operators will avoid using it."""
    user = _user(db)
    _vehicle(db, user)
    _api_key(db, user)

    user.is_active = False
    db.commit()
    assert "user CAR1" not in _acl_for(db, tmp_path)

    user.is_active = True
    db.commit()

    acl = _acl_for(db, tmp_path)
    assert "user CAR1" in acl
    assert "topic readwrite ovms/mallory/CAR1/#" in acl


def test_other_owners_are_unaffected_by_a_deactivation(db, tmp_path):
    """The filter must key on the owner, not drop everyone's rules."""
    mallory = _user(db, "mallory")
    _vehicle(db, mallory, "CAR1")
    alice = _user(db, "alice")
    _vehicle(db, alice, "CAR2")
    _api_key(db, alice, "efgh5678")

    mallory.is_active = False
    db.commit()

    acl = _acl_for(db, tmp_path)

    assert "ovms/mallory" not in acl
    assert "topic readwrite ovms/alice/CAR2/#" in acl
    assert "user efgh5678" in acl


def test_v2_tcp_auth_rejects_a_deactivated_owner():
    """
    The V2 handler must consult the owner's activation state. Asserted at import
    level: driving a real TCP handshake needs a socket, a cipher and a running
    server, and the property here is simply that the check exists in the path
    between the vehicle lookup and the password comparison.
    """
    import inspect

    from app.protocols.v2 import auth as v2_auth

    source = inspect.getsource(v2_auth.handle_authentication)

    lookup = source.index("get_vehicle_by_vehicle_id")
    compare = source.index("hmac.compare_digest")
    guard = source.index("owner.is_active")

    assert lookup < guard < compare, (
        "the owner activation check must sit between the vehicle lookup and the "
        "password comparison"
    )


def test_deactivation_queues_a_broker_resync(db, monkeypatch):
    """
    Filtering the ACL is useless if nothing regenerates it. Before the fix only a
    username change queued a rebuild, so a deactivated account kept full MQTT access
    until the process happened to restart.
    """
    from app.models import api as models_api
    from app.services import mqtt_sync_worker as worker_module

    user = _user(db)
    _vehicle(db, user)

    queued = {"vehicles": [], "acl": 0}
    monkeypatch.setattr(
        worker_module.mqtt_sync_worker, "mark_vehicle_dirty",
        lambda vehicle_id, acl=True: queued["vehicles"].append(vehicle_id),
    )
    monkeypatch.setattr(
        worker_module.mqtt_sync_worker, "mark_acl_dirty",
        lambda: queued.__setitem__("acl", queued["acl"] + 1),
    )

    crud.user.update_user(db, user, models_api.UserUpdate(is_active=False))

    assert queued["acl"] >= 1, "deactivation did not queue an ACL rebuild"
    assert "CAR1" in queued["vehicles"], "deactivation did not queue a vehicle resync"


def test_unrelated_update_does_not_queue_a_resync(db, monkeypatch):
    """Guards against 'fixing' this by rebuilding the ACL on every user write."""
    from app.models import api as models_api
    from app.services import mqtt_sync_worker as worker_module

    user = _user(db)
    _vehicle(db, user)

    queued = {"acl": 0}
    monkeypatch.setattr(
        worker_module.mqtt_sync_worker, "mark_acl_dirty",
        lambda: queued.__setitem__("acl", queued["acl"] + 1),
    )
    monkeypatch.setattr(
        worker_module.mqtt_sync_worker, "mark_vehicle_dirty",
        lambda vehicle_id, acl=True: None,
    )

    crud.user.update_user(db, user, models_api.UserUpdate(full_name="Mallory M"))

    assert queued["acl"] == 0


# ---------------------------------------------------------------------------
# N-8 — a password reset must revoke provisioned device keys
# ---------------------------------------------------------------------------


def test_password_reset_revokes_device_keys(db):
    user = _user(db)
    _api_key(db, user, "devicekey", device=True)

    crud.user.reset_user_password(db, user, "BrandNew1!Password")

    remaining = db.query(models_db.ApiKey).filter(
        models_db.ApiKey.user_id == user.id,
        models_db.ApiKey.is_device_key == True,
    ).all()
    assert remaining == [], "the attacker's provisioned device key survived the reset"


def test_password_reset_keeps_hand_made_api_keys(db):
    """
    Only device keys go. A key the user created by hand may be driving a home
    automation setup; breaking those on every reset would train people not to reset.
    """
    user = _user(db)
    _api_key(db, user, "devicekey", device=True)
    _api_key(db, user, "scripted1", device=False)

    crud.user.reset_user_password(db, user, "BrandNew1!Password")

    names = {k.key_prefix for k in db.query(models_db.ApiKey).filter_by(user_id=user.id).all()}
    assert names == {"scripted1"}


def test_password_reset_still_revokes_sessions(db):
    """The existing token_version guarantee must not regress while adding the above."""
    user = _user(db)
    before = user.token_version or 0

    crud.user.reset_user_password(db, user, "BrandNew1!Password")

    assert user.token_version == before + 1


def test_password_reset_does_not_touch_another_users_device_key(db):
    user = _user(db, "mallory")
    _api_key(db, user, "mallory01", device=True)
    other = _user(db, "alice")
    _api_key(db, other, "alice0001", device=True)

    crud.user.reset_user_password(db, user, "BrandNew1!Password")

    survivors = {k.key_prefix for k in db.query(models_db.ApiKey).all()}
    assert survivors == {"alice0001"}


def test_revoke_device_keys_is_a_noop_without_any(db):
    user = _user(db)
    assert crud_apikey.revoke_device_keys_for_user(db, user_id=user.id) == 0


# ---------------------------------------------------------------------------
# N-9 — per-account rate limiting must cover TOTP, not just login
# ---------------------------------------------------------------------------


def test_totp_failures_block_the_account_across_ips(db):
    """
    The whole point: every attempt comes from a different address, so the per-IP
    limit never fires. Only a per-account counter can see this.
    """
    threshold = security_manager._username_failure_thresholds["totp"]

    for i in range(threshold):
        assert not security_manager.is_username_blocked("victim")
        security_manager.record_failure(f"10.0.0.{i}", "totp", username="victim")

    assert security_manager.is_username_blocked("victim"), (
        "TOTP guesses spread across addresses never blocked the account"
    )


def test_totp_budget_is_tighter_than_the_login_budget(db):
    """
    Reaching the TOTP step already required a valid password, so those guesses come
    from someone demonstrably closer to the account.
    """
    assert (
        security_manager._username_failure_thresholds["totp"]
        < security_manager._username_failure_thresholds["login"]
    )


def test_totp_block_does_not_leak_onto_another_account(db):
    threshold = security_manager._username_failure_thresholds["totp"]

    for i in range(threshold):
        security_manager.record_failure(f"10.0.0.{i}", "totp", username="victim")

    assert security_manager.is_username_blocked("victim")
    assert not security_manager.is_username_blocked("bystander")


def test_login_and_totp_failures_do_not_share_one_budget(db):
    """
    Separate counters. Folding them together would let a handful of typos at each
    step add up to a lockout well before either threshold.
    """
    for i in range(security_manager._username_failure_thresholds["totp"] - 1):
        security_manager.record_failure(f"10.0.0.{i}", "totp", username="victim")
    for i in range(security_manager._username_failure_thresholds["login"] - 1):
        security_manager.record_failure(f"10.1.0.{i}", "login", username="victim")

    assert not security_manager.is_username_blocked("victim")


def test_ui_totp_route_records_the_username():
    """
    The counter only works if the caller supplies the account. The UI handler used to
    call record_failure(client_ip, 'totp') with no username at all, which left the new
    per-account limit dead on the most-used path — the same shape of bug as H-1.
    """
    import inspect

    from app.routers.ui import auth as ui_auth

    source = inspect.getsource(ui_auth)

    assert "record_failure(client_ip, 'totp', username=user.username)" in source, (
        "the UI TOTP handler must feed the username into the rate limiter"
    )


def test_ui_totp_route_checks_the_username_block():
    """Recording without enforcing would be another dead path."""
    import inspect

    from app.routers.ui import auth as ui_auth

    source = inspect.getsource(ui_auth.ui_login_totp_submit_route)

    assert "is_username_blocked" in source, (
        "the UI TOTP handler must reject submissions for a blocked account"
    )


def test_stale_totp_entries_are_swept(db):
    """The per-account map is keyed on attacker-supplied usernames; it must not grow."""
    security_manager.record_failure("10.0.0.1", "totp", username="victim")
    assert security_manager._username_failures["totp"]

    bucket = security_manager._username_failures["totp"]
    bucket["victim"] = [0.0]  # far outside any window

    security_manager.sweep_stale_username_entries()

    assert "victim" not in security_manager._username_failures["totp"]
