"""
When one device opens the app, the server clears the account's unread count and tells
the user's *other* devices, silently: iOS gets a badge-only push (`aps.badge = 0`, no
alert, no `mutable-content`), Android and UnifiedPush a `badge_reset` data message the
app answers by cancelling its notifications. Only when a count was actually cleared, and
never to the device that asked.
"""

import asyncio
import json

import pytest
from fastapi import BackgroundTasks
from firebase_admin import messaging

from app.database import Base, SessionLocal, engine
from app.models import db as models_db
from app.notifications import dispatcher
from app.notifications.channels import apns as apns_channel
from app.notifications.channels import fcm as fcm_channel
from app.notifications.channels import unified_push as up_channel
from app.notifications.errors import TransientDeliveryError
from app.routers.api import main as api_main
from app.services.charge_logger import models as _charge_models  # noqa: F401 - Vehicle's relationships
from app.widget_push_service import BadgeService


# ---------------------------------------------------------------------------
# what goes over the wire
# ---------------------------------------------------------------------------

@pytest.fixture
def fcm_sent(monkeypatch):
    sent = []
    monkeypatch.setattr(fcm_channel, "_firebase_app_initialized", True)

    def _send(message, *args, **kwargs):
        sent.append(json.loads(json.dumps(message, cls=messaging._messaging_encoder.MessageEncoder)))
        return "projects/test/messages/1"

    monkeypatch.setattr(fcm_channel.messaging, "send", _send)
    return sent


def test_fcm_badge_reset_is_silent_on_both_platforms(fcm_sent):
    assert fcm_channel.send_fcm_badge_reset("tok-any")

    (wire,) = fcm_sent
    assert "notification" not in wire, "a notification block would be shown"
    assert wire["data"] == {"type": "badge_reset"}
    assert wire["android"] == {"priority": "high", "ttl": "0s"}
    assert wire["apns"]["payload"] == {"aps": {"badge": 0}}
    assert wire["apns"]["headers"] == {
        "apns-push-type": "alert", "apns-priority": "10", "apns-expiration": "0"}


def test_apns_via_fcm_badge_reset_carries_its_type_in_the_payload(fcm_sent):
    assert fcm_channel.send_fcm_badge_reset("tok-ios", is_apns_token=True)

    (wire,) = fcm_sent
    assert wire["apns"]["payload"] == {"aps": {"badge": 0}, "type": "badge_reset"}
    assert "android" not in wire


def test_direct_apns_badge_reset_is_badge_only(monkeypatch):
    sent = []

    class _Client:
        def send(self, device_token, payload, topic=None, **kwargs):
            sent.append((payload, kwargs))

    monkeypatch.setattr(apns_channel, "_apns_client", _Client())
    assert apns_channel.send_apns_badge_reset("tok-123")

    (payload, kwargs), = sent
    assert payload == {"aps": {"badge": 0}, "type": "badge_reset"}
    assert kwargs == {"push_type": "alert", "priority": 10, "expiration": 0}


def test_unified_push_badge_reset(monkeypatch):
    posted = []

    def _post(url, **kwargs):
        posted.append((url, kwargs))
        return 201, ""

    monkeypatch.setattr(up_channel, "post", _post)
    assert up_channel.send_unified_push_badge_reset("https://up.example/abc")

    (url, kwargs), = posted
    assert kwargs["json"] == {"type": "badge_reset", "badge": 0}
    assert kwargs["headers"] == {"TTL": "0"}


# ---------------------------------------------------------------------------
# who gets one
# ---------------------------------------------------------------------------

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
    db.query(models_db.PushSubscription).delete()
    db.query(models_db.Vehicle).delete()
    db.query(models_db.User).delete()
    db.commit()
    yield


def _user(db, name):
    user = models_db.User(username=name, email=f"{name}@example.com",
                          hashed_password="x", is_active=True)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _vehicle(db, owner, vehicle_id, badge=0):
    vehicle = models_db.Vehicle(vehicle_id=vehicle_id, owner_id=owner.id, protocol="both",
                                encrypted_server_password=b"x", badge_count=badge)
    db.add(vehicle)
    db.commit()
    db.refresh(vehicle)
    return vehicle


def _sub(db, vehicle, device_id, push_type, endpoint):
    db.add(models_db.PushSubscription(vehicle_id_fk=vehicle.id, device_id=device_id,
                                      push_type=push_type, endpoint=endpoint))
    db.commit()


def test_the_plan_reaches_every_other_device_once(db, monkeypatch):
    monkeypatch.setattr(dispatcher.settings, "APNS_DELIVERY_METHOD", "apns")
    owner = _user(db, "owner")
    stranger = _user(db, "stranger")
    car_a = _vehicle(db, owner, "CARA")
    car_b = _vehicle(db, owner, "CARB")
    other = _vehicle(db, stranger, "CARX")

    # The asking phone, subscribed for both cars.
    _sub(db, car_a, "phone-1", "fcm", "tok-phone-1")
    _sub(db, car_b, "phone-1", "fcm", "tok-phone-1")
    # A second phone, subscribed for both cars: reset once.
    _sub(db, car_a, "phone-2", "fcm", "tok-phone-2")
    _sub(db, car_b, "phone-2", "fcm", "tok-phone-2")
    _sub(db, car_a, "tablet", "up", "https://up.example/t")
    _sub(db, car_b, "mac", "apns", "apns-tok")
    # Channels without a badge, and somebody else's device.
    _sub(db, car_a, "ntfy", "ntfy", "topic")
    _sub(db, car_a, "mail", "email", "owner@example.com")
    _sub(db, other, "foreign", "fcm", "tok-foreign")

    targets = dispatcher.build_badge_reset_plan(db, owner.id, exclude_device_id="phone-1")

    sent = sorted((t.sender.__name__, next(iter(t.kwargs.values()))) for t in targets)
    assert sent == [
        ("send_apns_badge_reset", "apns-tok"),
        ("send_fcm_badge_reset", "tok-phone-2"),
        ("send_unified_push_badge_reset", "https://up.example/t"),
    ]


def test_apns_tunnelled_through_fcm(db, monkeypatch):
    monkeypatch.setattr(dispatcher.settings, "APNS_DELIVERY_METHOD", "fcm")
    owner = _user(db, "owner")
    car = _vehicle(db, owner, "CARA")
    _sub(db, car, "mac", "apns", "apns-tok")

    (target,) = dispatcher.build_badge_reset_plan(db, owner.id)
    assert target.sender is fcm_channel.send_fcm_badge_reset
    assert target.kwargs == {"device_token": "apns-tok", "is_apns_token": True}


def test_a_reset_is_never_retried(db, monkeypatch):
    """TTL 0 means now or never. A retry booked for 5-60 s later could land after a newer
    alert and clear it — the badge to 0 on iOS, the notification out of the shade on
    Android — so a transient failure drops the reset, as the push service would."""
    owner = _user(db, "owner")
    car = _vehicle(db, owner, "CARA")
    _sub(db, car, "phone-2", "fcm", "tok-phone-2")

    booked = []
    monkeypatch.setattr(dispatcher._retry_scheduler, "schedule",
                        lambda delay, fn: booked.append(delay) or True)

    def _send(device_token, is_apns_token=False):
        raise TransientDeliveryError("HTTP 503")

    monkeypatch.setattr(dispatcher, "send_fcm_badge_reset", _send)
    (target,) = dispatcher.build_badge_reset_plan(db, owner.id)
    assert target.retry is False

    assert dispatcher.dispatch_badge_reset(owner.id) == 1
    assert booked == []


def test_a_dead_device_is_reaped_from_its_own_vehicle(db, monkeypatch):
    owner = _user(db, "owner")
    car_a = _vehicle(db, owner, "CARA")
    car_b = _vehicle(db, owner, "CARB")
    _sub(db, car_b, "gone", "fcm", "tok-gone")
    _sub(db, car_a, "fine", "fcm", "tok-fine")

    def _send(device_token, is_apns_token=False):
        if device_token == "tok-gone":
            raise dispatcher.InvalidPushTargetError("unregistered")
        return True

    monkeypatch.setattr(dispatcher, "send_fcm_badge_reset", _send)
    assert dispatcher.dispatch_badge_reset(owner.id) == 2

    db.expire_all()
    left = {s.endpoint for s in db.query(models_db.PushSubscription).all()}
    assert left == {"tok-fine"}


def test_a_dead_token_is_reaped_from_every_vehicle_it_follows(db, monkeypatch):
    """One device, three cars: one subscription per car, one reset for the token —
    and when the token is dead, all three rows go, the one the legacy migration
    filed under device 'legacy' included, not just the row the reset went out on."""
    owner = _user(db, "owner")
    cars = [_vehicle(db, owner, f"CAR{i}") for i in range(3)]
    for car in cars[:2]:
        _sub(db, car, "phone", "fcm", "tok-gone")
    _sub(db, cars[2], "legacy", "fcm", "tok-gone")
    _sub(db, cars[0], "tablet", "fcm", "tok-fine")
    _sub(db, cars[0], "phone", "up", "tok-gone")

    sent = []

    def _send(device_token, is_apns_token=False):
        sent.append(device_token)
        if device_token == "tok-gone":
            raise dispatcher.InvalidPushTargetError("unregistered")
        return True

    monkeypatch.setattr(dispatcher, "send_fcm_badge_reset", _send)
    monkeypatch.setattr(dispatcher, "send_unified_push_badge_reset", lambda endpoint_url: True)
    assert dispatcher.dispatch_badge_reset(owner.id) == 3
    assert sorted(sent) == ["tok-fine", "tok-gone"]

    db.expire_all()
    left = {(s.push_type, s.endpoint) for s in db.query(models_db.PushSubscription).all()}
    # The UnifiedPush endpoint is another target, even though it shares the string.
    assert left == {("fcm", "tok-fine"), ("up", "tok-gone")}


def test_a_push_counted_after_the_reset_cancels_it(db, monkeypatch):
    """The counter is cleared before the response and the reset goes out after it. A
    push counted in between reaches the other devices with the new figure, and a reset
    arriving after it would clear exactly that push — so none is sent."""
    owner = _user(db, "owner")
    car = _vehicle(db, owner, "CARA", badge=1)
    _sub(db, car, "phone-2", "fcm", "tok-phone-2")

    sent = []
    monkeypatch.setattr(dispatcher, "send_fcm_badge_reset",
                        lambda device_token, is_apns_token=False: sent.append(device_token) or True)

    assert dispatcher.dispatch_badge_reset(owner.id) == 0
    assert sent == []

    car.badge_count = 0
    db.commit()
    assert dispatcher.dispatch_badge_reset(owner.id) == 1
    assert sent == ["tok-phone-2"]


# ---------------------------------------------------------------------------
# the endpoint
# ---------------------------------------------------------------------------

def _reset(user, device_id):
    tasks = BackgroundTasks()
    body = api_main.BadgeResetRequest(device_id=device_id) if device_id else None
    result = asyncio.run(api_main.api_reset_all_badge_counts(
        background_tasks=tasks, body=body, db=None, current_user=user))
    return result, tasks


def test_a_reset_that_cleared_something_tells_the_other_devices(db):
    owner = _user(db, "owner")
    _vehicle(db, owner, "CARA", badge=5)

    result, tasks = _reset(owner, "phone-1")
    assert result["vehicles_reset"] == 1
    (task,) = tasks.tasks
    assert task.func is api_main.notifications.dispatch_badge_reset
    assert task.args == (owner.id, "phone-1")


def test_a_reset_with_nothing_to_clear_sends_nothing(db):
    owner = _user(db, "owner")
    _vehicle(db, owner, "CARA")

    result, tasks = _reset(owner, "phone-1")
    assert result["vehicles_reset"] == 0
    assert tasks.tasks == []


def test_the_second_reset_finds_nothing(db):
    owner = _user(db, "owner")
    _vehicle(db, owner, "CARA", badge=2)
    assert BadgeService().reset_all_badge_counts_for_user(owner.id) == 1
    assert BadgeService().reset_all_badge_counts_for_user(owner.id) == 0
