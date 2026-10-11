"""
The end of a support grant reaches what no request re-checks.

* `expire_due_grants()` clears only due rows, files SUPPORT_MODE_EXPIRED, and
  leaves a row the owner extended meanwhile alone (the clear is conditional);
* `withdraw_topic_from_others()` takes a `vehicle:` topic from the admins' sockets
  and keeps the owner's — `drop_topic()` would have cut the owner too;
* a WebSocket subscribe is authorized by the same gate: refused without a grant,
  accepted and audited with one;
* the lifespan loop survives a pass that raises.
"""

import asyncio
import datetime
from types import SimpleNamespace

import msgpack
import pytest
from starlette.websockets import WebSocketState

from app import lifespan
from app.database import Base, SessionLocal, engine
from app.models import db as models_db
from app.routers import ws as ws_router
from app.services import support_mode
from app.websocket_manager import WebSocketConnectionManager

NOW = datetime.datetime.now(datetime.timezone.utc)


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
def _clean(db, monkeypatch):
    db.query(models_db.Vehicle).delete()
    db.query(models_db.SecurityEvent).delete()
    db.query(models_db.User).delete()
    db.commit()
    support_mode.reset_throttles()
    withdrawn = []
    monkeypatch.setattr(support_mode.websocket_manager, "withdraw_topic_from_others_threadsafe",
                        lambda topic, keep: withdrawn.append((topic, keep)) or True)
    yield withdrawn
    support_mode.reset_throttles()


@pytest.fixture
def withdrawn(_clean):
    return _clean


def _owner_and_admin(db):
    alice = models_db.User(username="alice", email="a@example.com", hashed_password="x", is_active=True)
    root = models_db.User(username="root", email="r@example.com", hashed_password="x", is_active=True, is_admin=True)
    db.add_all([alice, root])
    db.commit()
    return alice, root


def _vehicle(db, owner, vid, until):
    vehicle = models_db.Vehicle(vehicle_id=vid, owner_id=owner.id, protocol="v3", encrypted_server_password=b"x",
                                support_until=until, support_granted_by_id=owner.id if until else None)
    db.add(vehicle)
    db.commit()
    return vehicle


def test_only_due_grants_are_cleared(db, withdrawn):
    alice, _ = _owner_and_admin(db)
    _vehicle(db, alice, "DUE", NOW - datetime.timedelta(minutes=1))
    _vehicle(db, alice, "RUNNING", NOW + datetime.timedelta(hours=1))

    assert support_mode.expire_due_grants() == ["DUE"]

    db.expire_all()
    due = db.query(models_db.Vehicle).filter_by(vehicle_id="DUE").one()
    running = db.query(models_db.Vehicle).filter_by(vehicle_id="RUNNING").one()
    assert due.support_until is None and due.support_granted_by_id is None
    assert running.support_until is not None
    events = db.query(models_db.SecurityEvent).filter_by(event_type="support_mode_expired").all()
    assert [e.details["vehicle_id"] for e in events] == ["DUE"]
    assert events[0].user_id == alice.id
    assert withdrawn == [("vehicle:DUE", alice.id)]


def test_a_grant_extended_meanwhile_is_kept(db, withdrawn):
    alice, _ = _owner_and_admin(db)
    _vehicle(db, alice, "RACE", NOW - datetime.timedelta(minutes=1))
    # The pass sees the grant due at `now`, but the owner extended it before the clear.
    later = NOW + datetime.timedelta(hours=5)
    db.query(models_db.Vehicle).filter_by(vehicle_id="RACE").update({"support_until": later})
    db.commit()
    assert support_mode.expire_due_grants(now=NOW) == []
    db.expire_all()
    assert db.query(models_db.Vehicle).filter_by(vehicle_id="RACE").one().support_until is not None
    assert withdrawn == []


def test_nothing_due_is_nothing(db, withdrawn):
    alice, _ = _owner_and_admin(db)
    _vehicle(db, alice, "NOGRANT", None)
    assert support_mode.expire_due_grants() == []
    assert withdrawn == []


# --- the sockets -------------------------------------------------------------------

class FakeWebSocket:
    def __init__(self):
        self.sent = []
        self.closed_with = None
        self.application_state = WebSocketState.CONNECTED
        self.client_state = WebSocketState.CONNECTED

    async def accept(self):
        pass

    async def send_bytes(self, data):
        self.sent.append(msgpack.unpackb(data, raw=False))

    async def close(self, code: int = 1000, reason=None):
        self.closed_with = code
        self.application_state = WebSocketState.DISCONNECTED


def test_withdrawal_keeps_the_owners_sockets():
    async def scenario():
        manager = WebSocketConnectionManager()
        owner_tab, owner_phone, admin, stray = FakeWebSocket(), FakeWebSocket(), FakeWebSocket(), FakeWebSocket()
        await manager.connect(owner_tab, "alice_1", user_id=1)
        await manager.connect(owner_phone, "alice_2", user_id=1)
        await manager.connect(admin, "root_1", user_id=2)
        await manager.connect(stray, "unknown_1")  # no account mapping: fails closed
        for cid in ("alice_1", "alice_2", "root_1", "unknown_1"):
            await manager.subscribe(cid, "vehicle:CAR1")
        await manager.subscribe("root_1", "vehicle:OTHER")

        assert await manager.withdraw_topic_from_others("vehicle:CAR1", keep_user_id=1) == 2

        assert manager.subscriptions["vehicle:CAR1"] == {"alice_1", "alice_2"}
        assert manager.subscriptions["vehicle:OTHER"] == {"root_1"}
        assert admin.sent == [{"type": "subscribe_rejected", "topic": "vehicle:CAR1"}]
        assert stray.sent == [{"type": "subscribe_rejected", "topic": "vehicle:CAR1"}]
        assert owner_tab.sent == [] and owner_phone.sent == []
        assert admin.closed_with is None

    asyncio.run(scenario())


def test_withdrawal_from_nobody_is_nothing():
    async def scenario():
        manager = WebSocketConnectionManager()
        tab = FakeWebSocket()
        await manager.connect(tab, "alice_1", user_id=1)
        await manager.subscribe("alice_1", "vehicle:CAR1")
        assert await manager.withdraw_topic_from_others("vehicle:CAR1", keep_user_id=1) == 0
        assert await manager.withdraw_topic_from_others("vehicle:NONE", keep_user_id=1) == 0
        assert manager.subscriptions == {"vehicle:CAR1": {"alice_1"}}

    asyncio.run(scenario())


def test_an_admin_subscribe_follows_the_grant(db):
    alice, root = _owner_and_admin(db)
    vehicle = _vehicle(db, alice, "LIVECAR", None)
    admin = SimpleNamespace(id=root.id, username="root", is_admin=True, is_active=True)

    assert ws_router._resolve_vehicle_topic("vehicle:LIVECAR", admin) is None

    vehicle.support_until = NOW + datetime.timedelta(hours=1)
    vehicle.support_granted_by_id = alice.id
    db.commit()
    assert ws_router._resolve_vehicle_topic("vehicle:livecar", admin) == "vehicle:LIVECAR"
    db.expire_all()
    events = db.query(models_db.SecurityEvent).filter_by(event_type="support_access").all()
    assert len(events) == 1 and events[0].details["kind"] == "live"


def test_the_expiry_loop_survives_a_failing_pass(monkeypatch):
    calls = []

    def flaky():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("database is locked")
        return []

    monkeypatch.setattr(support_mode, "expire_due_grants", flaky)
    monkeypatch.setattr(lifespan, "SUPPORT_EXPIRY_INTERVAL_SECONDS", 0)

    async def scenario():
        shutdown = asyncio.Event()
        task = asyncio.create_task(lifespan.periodic_support_expiry(shutdown))
        for _ in range(200):
            if len(calls) >= 2:
                break
            await asyncio.sleep(0.01)
        shutdown.set()
        await asyncio.wait_for(task, timeout=2)

    asyncio.run(scenario())
    assert len(calls) >= 2


def test_a_failed_audit_row_does_not_skip_the_next_grant(db, withdrawn, monkeypatch):
    """`log_event` commits the session it is handed. One that failed left the pass's
    session in a failed transaction, and the clear of the next due grant then raised
    PendingRollbackError: that grant stayed until the next minute, unwithdrawn."""
    from app import security_events

    alice, _ = _owner_and_admin(db)
    _vehicle(db, alice, "DUE1", NOW - datetime.timedelta(minutes=2))
    _vehicle(db, alice, "DUE2", NOW - datetime.timedelta(minutes=1))

    real_log_event = security_events.security_event_logger.log_event
    calls = []

    def failing_once(db, **kwargs):
        calls.append(kwargs["details"]["vehicle_id"])
        if len(calls) == 1:
            # What a failed INSERT leaves behind: a flush error inside the session.
            db.add(models_db.User(username=None, email=None, hashed_password=None))
            db.flush()
        return real_log_event(db=db, **kwargs)

    monkeypatch.setattr(security_events.security_event_logger, "log_event", failing_once)
    assert sorted(support_mode.expire_due_grants()) == ["DUE1", "DUE2"]
    db.expire_all()
    assert db.query(models_db.Vehicle).filter(models_db.Vehicle.support_until.isnot(None)).count() == 0
    assert sorted(t for t, _ in withdrawn) == ["vehicle:DUE1", "vehicle:DUE2"]


def test_a_subscription_that_slipped_past_the_withdrawal_is_taken_next_pass(db, withdrawn, monkeypatch):
    """A subscribe authorized while the grant ran, added after the owner ended it:
    the withdrawal found nothing then, and nothing checked the subscription again."""
    alice, root = _owner_and_admin(db)
    _vehicle(db, alice, "ENDED", None)
    _vehicle(db, alice, "RUNNING", NOW + datetime.timedelta(hours=1))
    _vehicle(db, alice, "OWNERONLY", None)
    ws = support_mode.websocket_manager
    monkeypatch.setattr(ws, "subscriptions", {
        "vehicle:ENDED": {"root_1", "alice_1"},
        "vehicle:RUNNING": {"root_1"},
        "vehicle:OWNERONLY": {"alice_1"},
        "vehicle:GONE": {"root_1"},
        "user:me": {"root_1"},
    })
    monkeypatch.setattr(ws, "connection_users", {"root_1": root.id, "alice_1": alice.id})

    assert support_mode.withdraw_lapsed_subscriptions() == ["vehicle:ENDED"]
    assert withdrawn == [("vehicle:ENDED", alice.id)]


def test_nothing_held_is_nothing_to_check(withdrawn, monkeypatch):
    monkeypatch.setattr(support_mode.websocket_manager, "subscriptions", {})
    assert support_mode.withdraw_lapsed_subscriptions() == []
    assert withdrawn == []
