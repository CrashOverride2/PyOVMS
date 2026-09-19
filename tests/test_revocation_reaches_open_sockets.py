"""
A revocation reaches the sockets that are already open.

A WebSocket is authenticated once, at its handshake, and a `vehicle:` subscription
is authorized once, when it is made; neither is ever re-checked. The logout closes
the account's sockets (tests/test_session_end_closes_sockets.py) — but every *other*
way a session or an authorization ends did not:

  * the token_version bump that ends every page session — a password change, a
    password reset, turning the second factor on or off. A reset is what someone
    does *after* losing control of the account, and the attacker's open tab was
    exactly the one that kept streaming live data (position included) and
    notifications until the token's own expiry;
  * an admin deactivating the account or revoking its admin rights — the log stream
    of a demoted admin ran on;
  * deleting the account, or a vehicle: the topic stayed on every socket that held
    it, and the next vehicle registered under the same id, by anyone, would have
    been streamed to the previous owner's open dashboard.

Now `crud.user` closes the account's sockets wherever it ends its sessions, and
`crud.vehicle` withdraws the topic of a deleted (or renamed) vehicle from every
socket, with the same `subscribe_rejected` frame a refused subscribe earns, so the
page drops it from its resubscribe set. Also here, the two cost bounds on what a
socket may send: the length of a client-chosen topic string, which used to reach
the database and the log uncut, and the per-socket budget of `vehicle:` lookups
(`LookupThrottle`), without which subscribe-and-unsubscribe in a loop was one
threadpool query per message.
"""

import asyncio
import logging
import re
import threading
import time

import msgpack
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect, WebSocketState

from app import crud, security
from app.crud import user as crud_user, vehicle as crud_vehicle
from app.database import Base, SessionLocal, engine, get_db
from app.main import app
from app.models import api as models_api, db as models_db
from app.security_manager import security_manager
from app.websocket_manager import WebSocketConnectionManager, manager as ws_manager, vehicle_topic

PASSWORD = "CorrectHorse1!Battery"
NEW_PASSWORD = "AnotherHorse2!Staple"


class FakeWebSocket:
    def __init__(self):
        self.application_state = WebSocketState.CONNECTED
        self.client_state = WebSocketState.CONNECTED
        self.closed_with = None
        self.sent = []

    async def accept(self):
        pass

    async def send_bytes(self, data):
        self.sent.append(msgpack.unpackb(data, raw=False))

    async def close(self, code: int = 1000, reason: str | None = None):
        self.closed_with = code
        self.application_state = WebSocketState.DISCONNECTED


# ---------------------------------------------------------------------------
# the manager: withdrawing a topic
# ---------------------------------------------------------------------------

def test_drop_topic_tells_every_subscriber_and_leaves_the_sockets_open():
    async def scenario():
        manager = WebSocketConnectionManager()
        alice, admin, bob = FakeWebSocket(), FakeWebSocket(), FakeWebSocket()
        await manager.connect(alice, "alice_1", user_id=1)
        await manager.connect(admin, "admin_1", user_id=2)
        await manager.connect(bob, "bob_1", user_id=3)
        await manager.subscribe("alice_1", "vehicle:CAR1")
        await manager.subscribe("alice_1", "user:1")
        await manager.subscribe("admin_1", "vehicle:CAR1")
        await manager.subscribe("bob_1", "vehicle:CAR2")

        told = await manager.drop_topic("vehicle:CAR1")

        assert told == 2
        assert "vehicle:CAR1" not in manager.subscriptions
        # The frame the page already understands as "drop it, do not ask again".
        assert alice.sent == [{"type": "subscribe_rejected", "topic": "vehicle:CAR1"}]
        assert admin.sent == [{"type": "subscribe_rejected", "topic": "vehicle:CAR1"}]
        assert bob.sent == []
        # Nobody was closed; the other subscriptions are as they were.
        assert alice.closed_with is None and admin.closed_with is None and bob.closed_with is None
        assert manager.subscriptions == {"user:1": {"alice_1"}, "vehicle:CAR2": {"bob_1"}}
        assert set(manager.active_connections) == {"alice_1", "admin_1", "bob_1"}

    asyncio.run(scenario())


def test_drop_topic_of_a_topic_nobody_holds_is_nothing():
    async def scenario():
        manager = WebSocketConnectionManager()
        assert await manager.drop_topic("vehicle:NOBODY") == 0
    asyncio.run(scenario())


def test_a_subscriber_that_cannot_be_told_is_reaped_like_any_failed_send():
    async def scenario():
        manager = WebSocketConnectionManager()
        broken, fine = FakeWebSocket(), FakeWebSocket()

        async def failing_send(data):
            raise RuntimeError("peer gone")

        broken.send_bytes = failing_send
        await manager.connect(broken, "broken_1", user_id=1)
        await manager.connect(fine, "fine_1", user_id=2)
        await manager.subscribe("broken_1", "vehicle:CAR1")
        await manager.subscribe("broken_1", "vehicle:CAR2")
        await manager.subscribe("fine_1", "vehicle:CAR1")

        await manager.drop_topic("vehicle:CAR1")

        assert "broken_1" not in manager.active_connections
        assert manager.subscriptions == {}
        assert fine.sent == [{"type": "subscribe_rejected", "topic": "vehicle:CAR1"}]

    asyncio.run(scenario())


def test_drop_topic_threadsafe_is_a_no_op_without_a_loop_or_a_subscriber():
    manager = WebSocketConnectionManager()
    assert manager.drop_topic_threadsafe("vehicle:CAR1") is False
    manager.subscriptions["vehicle:CAR1"] = {"alice_1"}
    assert manager.drop_topic_threadsafe("vehicle:CAR1") is False


def test_drop_topic_threadsafe_withdraws_from_a_request_thread():
    """crud.vehicle.delete_vehicle() runs on a worker thread; the sockets live on the loop."""
    async def scenario():
        manager = WebSocketConnectionManager()
        manager.bind_loop(asyncio.get_running_loop())
        ws = FakeWebSocket()
        await manager.connect(ws, "alice_1", user_id=1)
        await manager.subscribe("alice_1", "vehicle:CAR1")

        results = []
        worker = threading.Thread(target=lambda: results.append(manager.drop_topic_threadsafe("vehicle:CAR1")))
        worker.start()
        worker.join(timeout=2)

        for _ in range(100):
            if ws.sent:
                break
            await asyncio.sleep(0.01)
        assert results == [True]
        assert ws.sent == [{"type": "subscribe_rejected", "topic": "vehicle:CAR1"}]
        assert "vehicle:CAR1" not in manager.subscriptions
        assert ws.closed_with is None

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# crud: every path that ends a session, or frees a vehicle id, reaches the manager
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
    db.query(models_db.Vehicle).delete()
    db.query(models_db.ApiKey).delete()
    db.query(models_db.SecurityEvent).delete()
    db.query(models_db.User).delete()
    db.commit()
    security_manager.blocked_ips.clear()
    security_manager.failed_attempts.clear()
    ws_manager.subscriptions.clear()
    yield


@pytest.fixture
def manager_calls(monkeypatch):
    """
    What crud hands the manager. The TestClient runs no lifespan, so no loop is
    bound and the thread-safe calls would be no-ops; what is pinned is that they
    are made, for whom, and for which topics.
    """
    calls = {"disconnect": [], "drop": []}
    monkeypatch.setattr(ws_manager, "disconnect_user_threadsafe", lambda uid: calls["disconnect"].append(uid) or True)
    monkeypatch.setattr(ws_manager, "drop_topic_threadsafe", lambda topic: calls["drop"].append(topic) or True)
    return calls


def _make_user(db, username="alice", is_admin=False):
    user = models_db.User(
        username=username, email=f"{username}@example.com",
        hashed_password=security.get_password_hash(PASSWORD),
        is_active=True, is_admin=is_admin, is_totp_enabled=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _make_vehicle(db, owner, vehicle_id="CAR1"):
    vehicle = models_db.Vehicle(vehicle_id=vehicle_id, owner_id=owner.id, protocol="both",
                                encrypted_server_password=b"x")
    db.add(vehicle)
    db.commit()
    db.refresh(vehicle)
    return vehicle


def test_a_password_change_closes_the_accounts_sockets(db, manager_calls):
    user = _make_user(db)
    crud_user.update_user(db, user, models_api.UserUpdate(password=NEW_PASSWORD))
    assert manager_calls["disconnect"] == [user.id]


def test_a_password_reset_closes_the_accounts_sockets(db, manager_calls):
    user = _make_user(db)
    crud_user.reset_user_password(db, user, NEW_PASSWORD)
    assert manager_calls["disconnect"] == [user.id]


def test_a_change_to_the_second_factor_closes_the_accounts_sockets(db, manager_calls):
    user = _make_user(db)
    crud_user.enable_totp_for_user(db, user, security.generate_totp_secret())
    crud_user.disable_totp_for_user(db, user)
    assert manager_calls["disconnect"] == [user.id, user.id]


def test_bumping_the_token_version_closes_the_accounts_sockets(db, manager_calls):
    user = _make_user(db)
    crud_user.increment_token_version(db, user)
    assert manager_calls["disconnect"] == [user.id]


def test_deactivating_the_account_closes_its_sockets(db, manager_calls):
    user = _make_user(db)
    crud_user.update_user(db, user, models_api.UserUpdate(is_active=False))
    assert manager_calls["disconnect"] == [user.id]


def test_revoking_admin_rights_closes_the_sockets_including_the_log_stream(db, manager_calls):
    admin = _make_user(db, "root", is_admin=True)
    crud_user.update_user(db, admin, models_api.UserUpdate(is_admin=False))
    assert manager_calls["disconnect"] == [admin.id]


def test_an_edit_that_ends_no_session_leaves_the_sockets_alone(db, manager_calls):
    """A rename, a new address, a grant of admin rights, a reactivation: the acting
    tab must not be cut off for an edit that would not be refused at the next request."""
    user = _make_user(db)
    crud_user.update_user(db, user, models_api.UserUpdate(full_name="Alice Example", email="new@example.com"))
    crud_user.update_user(db, user, models_api.UserUpdate(is_admin=True))
    crud_user.update_user(db, user, models_api.UserUpdate(is_active=False))
    manager_calls["disconnect"].clear()
    crud_user.update_user(db, user, models_api.UserUpdate(is_active=True))
    assert manager_calls["disconnect"] == []
    assert manager_calls["drop"] == []


def test_deleting_the_account_closes_its_sockets_and_withdraws_its_vehicles(db, manager_calls):
    user = _make_user(db)
    other = _make_user(db, "bob")
    _make_vehicle(db, user, "CAR1")
    _make_vehicle(db, user, "CAR2")
    _make_vehicle(db, other, "BOB1")

    crud_user.delete_user(db, user.id)

    assert manager_calls["disconnect"] == [user.id]
    assert sorted(manager_calls["drop"]) == ["vehicle:CAR1", "vehicle:CAR2"]


def test_deleting_a_vehicle_withdraws_its_topic(db, manager_calls):
    user = _make_user(db)
    vehicle = _make_vehicle(db, user, "CAR1")
    crud_vehicle.delete_vehicle(db, vehicle.id)
    assert manager_calls["drop"] == ["vehicle:CAR1"]
    assert manager_calls["disconnect"] == []


def test_renaming_a_vehicle_withdraws_the_old_topic_and_an_ordinary_edit_does_not(db, manager_calls):
    user = _make_user(db)
    vehicle = _make_vehicle(db, user, "CAR1")
    crud_vehicle.update_vehicle(db, vehicle.id, models_api.VehicleUpdate(vehicle_name="Family car"))
    assert manager_calls["drop"] == []
    crud_vehicle.update_vehicle(db, vehicle.id, models_api.VehicleUpdate(vehicle_id="CAR9"))
    assert manager_calls["drop"] == ["vehicle:CAR1"]


# ---------------------------------------------------------------------------
# the batch lookup the broadcaster uses
# ---------------------------------------------------------------------------

def test_the_batch_lookup_returns_what_exists_keyed_by_id_whatever_the_case(db):
    user = _make_user(db)
    _make_vehicle(db, user, "CAR1")
    _make_vehicle(db, user, "CAR2")

    found = crud_vehicle.get_vehicles_by_vehicle_ids(db, ["car1", "CAR2", "CAR2", "GHOST"])

    assert set(found) == {"CAR1", "CAR2"}
    assert found["CAR1"].vehicle_id == "CAR1"
    assert crud_vehicle.get_vehicles_by_vehicle_ids(db, []) == {}


def test_the_batch_lookup_chunks_a_long_list(db, monkeypatch):
    user = _make_user(db)
    ids = [f"CAR{i}" for i in range(7)]
    for vehicle_id in ids:
        _make_vehicle(db, user, vehicle_id)
    monkeypatch.setattr(crud_vehicle, "_IDS_PER_QUERY", 3)

    found = crud_vehicle.get_vehicles_by_vehicle_ids(db, ids)

    assert set(found) == set(ids)


def test_the_broadcaster_builds_a_payload_for_every_watched_vehicle_in_one_lookup(db, monkeypatch):
    from app import lifespan

    user = _make_user(db)
    _make_vehicle(db, user, "CAR1")
    _make_vehicle(db, user, "CAR2")
    calls = []
    original = crud_vehicle.get_vehicles_by_vehicle_ids

    def counting(session, vehicle_ids):
        calls.append(list(vehicle_ids))
        return original(session, vehicle_ids)

    monkeypatch.setattr(crud.vehicle, "get_vehicles_by_vehicle_ids", counting)
    monkeypatch.setattr(crud.vehicle, "get_vehicle_by_vehicle_id",
                        lambda *a, **k: pytest.fail("one query per vehicle again"))

    built = lifespan._build_live_payloads(db, ["CAR1", "car2", "GHOST"])

    assert set(built) == {"CAR1", "car2"}
    assert calls == [["CAR1", "car2", "GHOST"]]


# ---------------------------------------------------------------------------
# over the socket
# ---------------------------------------------------------------------------

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


def _login(client, username="alice"):
    page = client.get("/login")
    token = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page.text) or \
        re.search(r'value="([^"]+)"[^>]*name="csrf_token"', page.text)
    assert token is not None
    response = client.post(
        "/login",
        data={"username": username, "password": PASSWORD, "csrf_token": token.group(1)},
        follow_redirects=False,
    )
    assert response.status_code in (302, 303, 307), response.text


def _connect(client):
    headers = {"origin": "https://testserver"}
    jar = "; ".join(f"{name}={value}" for name, value in client.cookies.items())
    if jar:
        headers["cookie"] = jar
    return client.websocket_connect("/ws", headers=headers)


def _wait_for_topics(topics, present=True, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if all((t in ws_manager.subscriptions) is present for t in topics):
            return True
        time.sleep(0.02)
    return all((t in ws_manager.subscriptions) is present for t in topics)


def test_a_vehicle_topic_is_held_under_the_stored_id_whatever_the_page_sent(client, db):
    """One vehicle, one topic: a withdrawal has to find every subscriber under one name."""
    user = _make_user(db)
    _make_vehicle(db, user, "CAR1")
    _login(client)
    with _connect(client) as ws:
        ws.send_json({"action": "subscribe", "topic": "vehicle:car1"})
        assert _wait_for_topics([vehicle_topic("CAR1")])
        assert "vehicle:car1" not in ws_manager.subscriptions


def test_an_overlong_topic_is_refused_before_it_is_looked_up(client, db, monkeypatch):
    from app.routers import ws as ws_module

    _make_user(db)
    _login(client)
    monkeypatch.setattr(ws_module, "_resolve_vehicle_topic",
                        lambda *a, **k: pytest.fail("looked up a topic that can name nothing"))
    with _connect(client) as ws:
        ws.send_json({"action": "subscribe", "topic": "vehicle:" + "X" * (ws_module._MAX_TOPIC_LENGTH + 1)})
        answer = msgpack.unpackb(ws.receive_bytes(), raw=False)
    assert answer["type"] == "subscribe_rejected"


def test_the_topic_bound_still_admits_the_longest_id_the_column_holds(client, db):
    from app.routers import ws as ws_module

    user = _make_user(db)
    longest = "V" * models_db.Vehicle.vehicle_id.type.length
    _make_vehicle(db, user, longest)
    _login(client)
    with _connect(client) as ws:
        ws.send_json({"action": "subscribe", "topic": vehicle_topic(longest)})
        assert _wait_for_topics([vehicle_topic(longest)])
    assert len(vehicle_topic(longest)) == ws_module._MAX_TOPIC_LENGTH


def test_an_overlong_unsubscribe_never_reaches_the_log_uncut(client, db, caplog):
    _make_user(db)
    _login(client)
    caplog.set_level(logging.INFO)
    with _connect(client) as ws:
        ws.send_json({"action": "unsubscribe", "topic": "vehicle:" + "x" * 100_000})
        with pytest.raises(WebSocketDisconnect):
            ws.receive_bytes()
    assert all(len(r.getMessage()) < 1000 for r in caplog.records)


def test_an_unsubscribe_finds_the_entry_whatever_case_the_page_used(client, db, monkeypatch):
    from app.routers import ws as ws_module

    user = _make_user(db)
    _make_vehicle(db, user, "CAR1")
    _login(client)
    lookups = []
    original = ws_module._resolve_vehicle_topic

    def counting(topic, current_user):
        lookups.append(topic)
        return original(topic, current_user)

    monkeypatch.setattr(ws_module, "_resolve_vehicle_topic", counting)
    with _connect(client) as ws:
        ws.send_json({"action": "subscribe", "topic": "vehicle:car1"})
        assert _wait_for_topics(["vehicle:CAR1"])
        # Held already, under the stored spelling: no second lookup.
        ws.send_json({"action": "subscribe", "topic": "vehicle:CAR1"})
        ws.send_json({"action": "unsubscribe", "topic": "vehicle:car1"})
        assert _wait_for_topics(["vehicle:CAR1"], present=False)
    assert lookups == ["vehicle:car1"]


# ---------------------------------------------------------------------------
# the per-socket lookup budget
# ---------------------------------------------------------------------------

class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_the_throttle_grants_the_burst_at_once_and_then_one_per_interval():
    from app.routers.ws import LookupThrottle

    clock = FakeClock()
    throttle = LookupThrottle(burst=3, per_second=2.0, clock=clock)

    assert [throttle.acquire() for _ in range(3)] == [0.0, 0.0, 0.0]
    # The fourth waits for one token: half a second at two per second.
    assert throttle.acquire() == pytest.approx(0.5)
    clock.now += 0.5
    # After the wait the debt is paid, and the next one owes another half second.
    assert throttle.acquire() == pytest.approx(0.5)
    # An idle socket earns its burst back, and no more than that.
    clock.now += 60
    assert [throttle.acquire() for _ in range(3)] == [0.0, 0.0, 0.0]
    assert throttle.acquire() > 0


def test_a_rate_of_zero_means_no_limit():
    from app.routers.ws import LookupThrottle

    throttle = LookupThrottle(burst=1, per_second=0, clock=FakeClock())
    assert [throttle.acquire() for _ in range(50)] == [0.0] * 50


@pytest.fixture
def recorded_delays(monkeypatch):
    """Every delay the endpoint's throttle handed out, without waiting on the clock."""
    from app.routers import ws as ws_module

    delays = []

    class Recording(ws_module.LookupThrottle):
        def acquire(self):
            delay = super().acquire()
            delays.append(delay)
            return delay

    monkeypatch.setattr(ws_module, "LookupThrottle", Recording)
    return delays


def test_a_dashboard_sized_burst_of_subscribes_never_waits(client, db, recorded_delays):
    user = _make_user(db)
    ids = [f"CAR{i}" for i in range(12)]
    for vehicle_id in ids:
        _make_vehicle(db, user, vehicle_id)
    _login(client)
    with _connect(client) as ws:
        for vehicle_id in ids:
            ws.send_json({"action": "subscribe", "topic": vehicle_topic(vehicle_id)})
        assert _wait_for_topics([vehicle_topic(v) for v in ids])
        # Re-sending the set, as a reconnecting page does, costs no budget: the
        # topics are held already and never reach the throttle.
        for vehicle_id in ids:
            ws.send_json({"action": "subscribe", "topic": vehicle_topic(vehicle_id)})
        ws.send_json({"action": "subscribe", "topic": "user:me"})
        assert _wait_for_topics([f"user:{user.id}"])
    assert recorded_delays == [0.0] * len(ids)


def test_subscribing_past_the_budget_is_delayed_and_never_refused(client, db, recorded_delays, monkeypatch):
    from app.config import settings

    user = _make_user(db)
    for vehicle_id in ("CAR1", "CAR2", "CAR3"):
        _make_vehicle(db, user, vehicle_id)
    monkeypatch.setattr(settings, "WS_SUBSCRIBE_LOOKUP_BURST", 1)
    monkeypatch.setattr(settings, "WS_SUBSCRIBE_LOOKUPS_PER_SECOND", 50.0)
    _login(client)
    started = time.monotonic()
    with _connect(client) as ws:
        for vehicle_id in ("CAR1", "CAR2", "CAR3"):
            ws.send_json({"action": "subscribe", "topic": vehicle_topic(vehicle_id)})
        assert _wait_for_topics([vehicle_topic(v) for v in ("CAR1", "CAR2", "CAR3")])
    assert recorded_delays[0] == 0.0
    assert all(delay > 0 for delay in recorded_delays[1:]), recorded_delays
    # Two lookups owed at fifty per second: the socket waited at least that long.
    assert time.monotonic() - started >= 2 / 50


def test_an_unsubscribe_and_resubscribe_loop_is_paced_by_the_budget(client, db, recorded_delays, monkeypatch):
    from app.config import settings

    user = _make_user(db)
    _make_vehicle(db, user, "CAR1")
    monkeypatch.setattr(settings, "WS_SUBSCRIBE_LOOKUP_BURST", 2)
    # Slow enough that the polling between the steps below refills less than a token.
    monkeypatch.setattr(settings, "WS_SUBSCRIBE_LOOKUPS_PER_SECOND", 5.0)
    _login(client)
    with _connect(client) as ws:
        for _ in range(6):
            ws.send_json({"action": "subscribe", "topic": "vehicle:CAR1"})
            assert _wait_for_topics(["vehicle:CAR1"])
            ws.send_json({"action": "unsubscribe", "topic": "vehicle:CAR1"})
            assert _wait_for_topics(["vehicle:CAR1"], present=False)
    assert len(recorded_delays) == 6
    assert recorded_delays[:2] == [0.0, 0.0]
    assert all(delay > 0 for delay in recorded_delays[2:]), recorded_delays
