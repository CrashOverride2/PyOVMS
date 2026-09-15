"""
Two lifecycle rules, both learned the hard way.

1. A registration whose verification link expired unused is deleted. Nothing did
   that before: the daily lifecycle pass only warns *active* users, and an account
   that never verified cannot log in, so it stayed forever — and with it the
   username and the address, which the registration form treats as taken (it
   answers a collision with the generic success page). One typo in the address
   locked the chosen username for good.

2. A vehicle that comes back after the 365-day warning has its mark cleared, on
   every protocol. The V3 subscriber wrote `last_seen_v3` straight into the column
   and left `unused_reminder_sent_at` set: the deletion pass itself re-checks
   last_seen and spared the vehicle, but the *next* time it went quiet for a year
   it was deleted on the spot — the warning is only sent while the mark is None.
   On V2 the opposite happened: an app authenticates with the vehicle's server
   password, and its connection counted as the car's activity.
"""

import datetime
import inspect
import textwrap
from types import SimpleNamespace

import pytest

from app import crud, lifespan
from app.connection_manager import ConnectionManager
from app.database import Base, SessionLocal, engine
from app.models import db as models_db
from app.mqtt_metrics_subscriber import MqttMetricsSubscriber
from app.protocols.v2 import auth as v2_auth
from app.utils import mqtt_topic_auth

UTC = datetime.timezone.utc


def _now() -> datetime.datetime:
    return datetime.datetime.now(UTC)


def _days_ago(days: float) -> datetime.datetime:
    return _now() - datetime.timedelta(days=days)


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
    mqtt_topic_auth.clear_cache()
    yield


def _make_user(db, username, *, active=True, admin=False, token_expires_at=None):
    user = models_db.User(
        username=username, email=f"{username}@example.com",
        hashed_password="x", is_active=active, is_admin=admin, is_totp_enabled=False,
        email_verification_token=("hash-" + username) if token_expires_at else None,
        email_verification_token_expires_at=token_expires_at,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _make_vehicle(db, owner, vehicle_id, *, last_seen_v3=None, last_seen_tcp=None, reminder=None):
    vehicle = models_db.Vehicle(
        vehicle_id=vehicle_id, owner_id=owner.id, protocol="both",
        encrypted_server_password=b"x",
        last_seen_v3=last_seen_v3, last_seen_tcp=last_seen_tcp,
        unused_reminder_sent_at=reminder,
    )
    db.add(vehicle)
    db.commit()
    db.refresh(vehicle)
    return vehicle


def _usernames(db) -> set[str]:
    return {u.username for u in db.query(models_db.User).all()}


# ---------------------------------------------------------------------------
# 1. Expired registrations are deleted
# ---------------------------------------------------------------------------


def test_expired_unverified_registration_is_deleted(db):
    _make_user(db, "typo", active=False, token_expires_at=_now() - datetime.timedelta(hours=1))

    removed = lifespan.purge_expired_registrations(db)

    assert removed == 1
    assert "typo" not in _usernames(db)


def test_deletion_of_an_expired_registration_is_audited(db):
    user = _make_user(db, "typo", active=False, token_expires_at=_now() - datetime.timedelta(hours=1))
    user_id = user.id

    lifespan.purge_expired_registrations(db)

    event = db.query(models_db.SecurityEvent).filter_by(event_type="user_deleted").one()
    assert event.username == "typo"
    assert event.user_id is None, "a dead id fails the insert on enforcing backends"
    assert event.details["reason"] == "verification_expired"
    assert event.details["deleted_user_id"] == user_id


def test_a_registration_whose_link_is_still_valid_is_kept(db):
    _make_user(db, "pending", active=False, token_expires_at=_now() + datetime.timedelta(hours=1))

    assert lifespan.purge_expired_registrations(db) == 0
    assert "pending" in _usernames(db)


def test_accounts_that_are_not_pending_registrations_are_never_touched(db):
    # Deactivated by an admin: inactive, but there is no verification token.
    _make_user(db, "disabled", active=False)
    # Activated by an admin before the link was used: the token is still there.
    _make_user(db, "hand-activated", active=True, token_expires_at=_days_ago(5))
    # Verified the normal way.
    _make_user(db, "verified", active=True)
    # Would match on every column but must be excluded on principle.
    _make_user(db, "boss", active=False, admin=True, token_expires_at=_days_ago(5))

    assert lifespan.purge_expired_registrations(db) == 0
    assert _usernames(db) == {"disabled", "hand-activated", "verified", "boss"}


def test_an_unverified_account_with_a_vehicle_is_left_alone(db):
    """Cannot happen through the registration flow; if it does, this pass must not
    be the thing that cascades into vehicle data."""
    owner = _make_user(db, "odd", active=False, token_expires_at=_days_ago(5))
    _make_vehicle(db, owner, "ODDCAR")

    assert lifespan.purge_expired_registrations(db) == 0
    assert "odd" in _usernames(db)


def test_a_freed_username_and_address_can_be_registered_again(db):
    _make_user(db, "typo", active=False, token_expires_at=_days_ago(2))
    lifespan.purge_expired_registrations(db)

    assert crud.user.get_user_by_username(db, "typo") is None
    assert crud.user.get_user_by_email(db, "typo@example.com") is None


def test_hourly_housekeeping_runs_the_purge():
    source = textwrap.dedent(inspect.getsource(lifespan.periodic_housekeeping))
    assert "purge_expired_registrations" in source


# ---------------------------------------------------------------------------
# 2. A returning vehicle loses its deletion mark
# ---------------------------------------------------------------------------


def _mqtt_message(topic: str, payload: bytes, retain: bool = False):
    return SimpleNamespace(topic=topic, payload=payload, retain=retain)


def test_v3_metric_clears_the_deletion_mark(db):
    owner = _make_user(db, "owner")
    _make_vehicle(db, owner, "V3CAR", last_seen_v3=_days_ago(400), reminder=_days_ago(10))
    assert [v.vehicle_id for v in crud.vehicle.get_vehicles_to_auto_delete(db)] == ["V3CAR"]

    subscriber = MqttMetricsSubscriber()
    subscriber._on_message(None, None, _mqtt_message("ovms/owner/V3CAR/metric/v/b/soc", b"80"))

    db.expire_all()
    vehicle = crud.vehicle.get_vehicle_by_vehicle_id(db, "V3CAR")
    assert vehicle.unused_reminder_sent_at is None
    assert vehicle.last_seen_v3 is not None
    assert crud.vehicle.get_vehicles_to_auto_delete(db) == []


def test_a_retained_v3_message_is_not_a_reconnect(db):
    """A retained message is the broker replaying the last value, of unknowable age."""
    owner = _make_user(db, "owner")
    _make_vehicle(db, owner, "V3CAR", last_seen_v3=_days_ago(400), reminder=_days_ago(10))

    subscriber = MqttMetricsSubscriber()
    subscriber._on_message(None, None, _mqtt_message("ovms/owner/V3CAR/metric/v/b/soc", b"80", retain=True))

    db.expire_all()
    vehicle = crud.vehicle.get_vehicle_by_vehicle_id(db, "V3CAR")
    assert vehicle.unused_reminder_sent_at is not None
    assert [v.vehicle_id for v in crud.vehicle.get_vehicles_to_auto_delete(db)] == ["V3CAR"]


def test_v2_last_seen_write_clears_the_deletion_mark(db):
    owner = _make_user(db, "owner")
    _make_vehicle(db, owner, "V2CAR", last_seen_tcp=_days_ago(400), reminder=_days_ago(10))

    crud.vehicle.update_vehicle_last_seen_tcp(db, "V2CAR")

    db.expire_all()
    vehicle = crud.vehicle.get_vehicle_by_vehicle_id(db, "V2CAR")
    assert vehicle.unused_reminder_sent_at is None
    assert crud.vehicle.get_vehicles_to_auto_delete(db) == []


def test_a_returned_vehicle_is_warned_again_before_its_next_deletion(db):
    """The point of clearing the mark: the second silence gets its own warning."""
    owner = _make_user(db, "owner")
    vehicle = _make_vehicle(db, owner, "V2CAR", last_seen_tcp=_days_ago(400), reminder=_days_ago(10))

    crud.vehicle.update_vehicle_last_seen_tcp(db, "V2CAR", timestamp=_days_ago(366))

    db.expire_all()
    assert [v.vehicle_id for v in crud.vehicle.get_vehicles_needing_unused_warning(db)] == ["V2CAR"]
    assert crud.vehicle.get_vehicles_to_auto_delete(db) == [], (
        "a vehicle that has not been warned must not be deleted"
    )


def _code_only(obj) -> str:
    """Source with comments and docstrings removed, so a sentence describing the
    behaviour cannot satisfy a check meant for the code."""
    import ast

    tree = ast.parse(textwrap.dedent(inspect.getsource(obj)))
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
                    and isinstance(body[0].value.value, str):
                body.pop(0)
    return ast.unparse(tree)


def test_v2_handshake_counts_cars_only():
    source = _code_only(v2_auth.handle_authentication)
    write = source.index("crud.vehicle.update_vehicle_last_seen_tcp")
    preceding_line = source[:write].rstrip().rsplit("\n", 1)[-1].strip()

    assert preceding_line == "if conn.client_type == 'C':", (
        "an app connection still counts as the car's last_seen"
    )


def test_add_connection_does_not_write_last_seen():
    """The handshake writes it, for cars only; a second write here covered apps too."""
    assert "update_vehicle_last_seen_tcp" not in _code_only(ConnectionManager.add_connection)
