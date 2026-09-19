"""
The dashboard shows live data without a reload.

Three things are pinned:

  * `build_vehicle_live_payload()` is the one shape the `vehicle:<id>` topic carries —
    the broadcaster and the dashboard's first render both use it, so the keys the page
    reads are asserted here by name;
  * the dashboard embeds that payload per card and opens no ticket, no second route:
    the page subscribes over `/ws`, which now takes any number of subscriptions on one
    socket, each authorized on its own;
  * an unauthorized subscribe in the middle of a multi-subscribe session is answered
    with `subscribe_rejected` for that topic alone: the socket and the subscriptions
    it already holds stay. Closing the socket instead meant one card whose vehicle
    had been deleted while the tab was open re-sent that subscribe on every reconnect
    and starved every other card of live data until reload; and it made the socket
    an oracle for vehicle ids, since a foreign and a missing vehicle had to look
    the same;
  * `lastMessageAt` is a `...Z` string on both halves of the DateTime(timezone=True)
    split — the tz-aware value PostgreSQL returns used to come out as `...+00:00Z`,
    which `new Date()` rejects, so every "last seen" on the dashboard read "Never".
"""

import asyncio
import datetime
import json
import re
import time

import pytest
from fastapi.testclient import TestClient
import msgpack
from starlette.websockets import WebSocketDisconnect

from app import security
from app.database import Base, SessionLocal, engine, get_db
from app.main import app
from app.metrics_manager import metrics_manager
from app.models import db as models_db
from app.security_manager import security_manager
from app.utils.timestamps import as_utc_iso
from app.utils.vehicle_live_payload import build_vehicle_live_payload
from app.websocket_manager import manager as ws_manager

PASSWORD = "CorrectHorse1!Battery"

# What index.html's card reads. A key removed here without the template following is
# a card that silently shows "–" for that field.
PAYLOAD_KEYS = {
    "isV2Online", "isV3Online", "soc", "units", "line_voltage", "charge_current",
    "charge_state_text", "charge_mode_text", "estimated_range", "battery_voltage",
    "battery_current", "battery_soh", "vehicle_12v", "lat", "lon", "lastMessageAt",
    "tpms_data", "v2_metrics", "v3_metrics",
}


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
    db.query(models_db.BlockedIP).delete()
    db.query(models_db.SecurityFailure).delete()
    db.commit()
    security_manager.blocked_ips.clear()
    security_manager.failed_attempts.clear()
    security_manager._blocked_usernames.clear()
    security_manager._username_failures.clear()
    metrics_manager.vehicle_metrics.clear()
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


def _make_vehicle(db, owner, vehicle_id="CAR1", **fields):
    vehicle = models_db.Vehicle(vehicle_id=vehicle_id, owner_id=owner.id, protocol="both",
                                encrypted_server_password=b"x", **fields)
    db.add(vehicle)
    db.commit()
    db.refresh(vehicle)
    return vehicle


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


# ---------------------------------------------------------------------------
# the payload
# ---------------------------------------------------------------------------

def test_the_payload_carries_exactly_the_keys_the_card_reads(db):
    user = _make_user(db)
    vehicle = _make_vehicle(db, user)

    payload = build_vehicle_live_payload(vehicle)

    assert set(payload) == PAYLOAD_KEYS
    assert payload["isV2Online"] is False and payload["isV3Online"] is False
    assert payload["lastMessageAt"] is None


def test_v3_metrics_reach_the_payload_as_status_and_verbatim(db):
    user = _make_user(db)
    vehicle = _make_vehicle(db, user)
    metrics_manager.update_metric("CAR1", "v.b.soc", "90")
    metrics_manager.update_metric("CAR1", "v.c.charging", "yes")
    metrics_manager.update_metric("CAR1", "v.c.power", "9.9")
    metrics_manager.update_metric("CAR1", "v.p.odometer", "62765")

    payload = build_vehicle_live_payload(vehicle)

    assert payload["soc"] == "90"
    # The card derives power, odometer and the charging flag from the raw metrics.
    assert payload["v3_metrics"]["v.c.power"] == "9.9"
    assert payload["v3_metrics"]["v.c.charging"] == "yes"
    assert payload["v3_metrics"]["v.p.odometer"] == "62765"


def test_the_payload_is_msgpack_safe(db):
    """The broadcaster packs it; a datetime or Decimal in here is a dropped broadcast."""
    import msgpack
    user = _make_user(db)
    vehicle = _make_vehicle(db, user)
    metrics_manager.update_metric("CAR1", "v.b.soc", "90")

    msgpack.packb(build_vehicle_live_payload(vehicle), use_bin_type=True)


# ---------------------------------------------------------------------------
# the page
# ---------------------------------------------------------------------------

def test_the_dashboard_embeds_the_live_payload_per_card(client, db):
    user = _make_user(db)
    _make_vehicle(db, user, "CAR1")
    _make_vehicle(db, user, "CAR2")
    metrics_manager.update_metric("CAR2", "v.b.soc", "42")
    _login(client)

    page = client.get("/dashboard")

    assert page.status_code == 200, page.text[:500]
    cards = re.findall(r'data-vehicle-id="([^"]+)"', page.text)
    assert cards == ["CAR1", "CAR2"]
    embedded = re.findall(r'<script type="application/json" class="js-live-payload">(.*?)</script>', page.text)
    assert len(embedded) == 2
    payloads = [json.loads(text) for text in embedded]
    assert set(payloads[0]) == PAYLOAD_KEYS
    assert payloads[1]["soc"] == "42"
    # The page opens the socket itself, with the cookie; there is no ticket to fetch.
    assert "dashboardVehicleCard" in page.text
    assert "ws-ticket" not in page.text
    # No inline script without a nonce.
    assert re.search(r"<script(?![^>]*\b(?:nonce|src|type=\"application/json\")=?)[^>]*>", page.text) is None


def test_another_owners_vehicle_is_not_on_the_dashboard(client, db):
    alice = _make_user(db, "alice")
    bob = _make_user(db, "bob")
    _make_vehicle(db, alice, "ALICE1")
    _make_vehicle(db, bob, "BOB1")
    _login(client, "alice")

    page = client.get("/dashboard")

    assert 'data-vehicle-id="ALICE1"' in page.text
    assert "BOB1" not in page.text


def test_a_metric_value_cannot_break_out_of_the_embedded_payload(client, db):
    """
    The payload goes into a <script type="application/json"> block verbatim, and a V3
    metric value is whatever the module published. `</script>` in one must not end the
    block: `tojson` writes it as \u003c/script\u003e, which JSON.parse reads back.
    """
    user = _make_user(db)
    _make_vehicle(db, user, "CAR1")
    metrics_manager.update_metric("CAR1", "v.type", "</script><script>alert(1)</script>")
    _login(client)

    page = client.get("/dashboard")

    assert page.status_code == 200
    assert "<script>alert(1)</script>" not in page.text
    embedded = re.search(r'<script type="application/json" class="js-live-payload">(.*?)</script>', page.text).group(1)
    assert json.loads(embedded)["v3_metrics"]["v.type"] == "</script><script>alert(1)</script>"


# ---------------------------------------------------------------------------
# several subscriptions on one socket
# ---------------------------------------------------------------------------

def test_one_socket_subscribes_to_every_vehicle_of_the_account(client, db):
    user = _make_user(db)
    _make_vehicle(db, user, "CAR1")
    _make_vehicle(db, user, "CAR2")
    _login(client)

    with _connect(client) as ws:
        ws.send_json({"action": "subscribe", "topic": "vehicle:CAR1"})
        ws.send_json({"action": "subscribe", "topic": "vehicle:CAR2"})
        ws.send_json({"action": "subscribe", "topic": "user:me"})
        assert _wait_for_topics(["vehicle:CAR1", "vehicle:CAR2", f"user:{user.id}"])

        ws.send_json({"action": "unsubscribe", "topic": "vehicle:CAR1"})
        assert _wait_for_topics(["vehicle:CAR1"], present=False)
        assert _wait_for_topics(["vehicle:CAR2"])

    assert _wait_for_topics(["vehicle:CAR2", f"user:{user.id}"], present=False), "subscriptions outlived the socket"


def _rejection(ws):
    return msgpack.unpackb(ws.receive_bytes(), raw=False)


def test_a_foreign_vehicle_in_the_middle_is_rejected_and_the_rest_stays(client, db):
    alice = _make_user(db, "alice")
    bob = _make_user(db, "bob")
    _make_vehicle(db, alice, "ALICE1")
    _make_vehicle(db, bob, "BOB1")
    _login(client, "alice")

    with _connect(client) as ws:
        ws.send_json({"action": "subscribe", "topic": "vehicle:ALICE1"})
        assert _wait_for_topics(["vehicle:ALICE1"])
        ws.send_json({"action": "subscribe", "topic": "vehicle:BOB1"})
        assert _rejection(ws) == {"type": "subscribe_rejected", "topic": "vehicle:BOB1"}
        assert "vehicle:BOB1" not in ws_manager.subscriptions
        assert "vehicle:ALICE1" in ws_manager.subscriptions, "the rejection cost the other card"
        # The socket is still a socket: a later subscribe on it lands.
        ws.send_json({"action": "subscribe", "topic": "user:me"})
        assert _wait_for_topics([f"user:{alice.id}"])

    assert _wait_for_topics(["vehicle:ALICE1", f"user:{alice.id}"], present=False)


def test_a_missing_vehicle_gets_the_same_answer_as_a_foreign_one(client, db):
    """A dashboard card whose vehicle is gone, and no oracle for vehicle ids."""
    _make_user(db, "alice")
    bob = _make_user(db, "bob")
    _make_vehicle(db, bob, "BOB1")
    _login(client, "alice")

    with _connect(client) as ws:
        ws.send_json({"action": "subscribe", "topic": "vehicle:NOPE"})
        missing = _rejection(ws)
        ws.send_json({"action": "subscribe", "topic": "vehicle:BOB1"})
        foreign = _rejection(ws)
        assert missing == {"type": "subscribe_rejected", "topic": "vehicle:NOPE"}
        assert foreign == {"type": "subscribe_rejected", "topic": "vehicle:BOB1"}
        assert set(missing) == set(foreign)


def test_a_socket_that_keeps_getting_refused_is_closed(client, db):
    """
    Every `vehicle:` subscribe is a database lookup on the threadpool, and nothing
    else bounds how many one authenticated client may send. A page earns one
    refusal per card whose vehicle vanished, so twenty in a row is not a page. The
    answers up to the cap are the ordinary rejection — the cap changes the cost of
    probing, not what a probe learns.
    """
    from app.routers import ws as ws_module

    _make_user(db, "alice")
    _login(client, "alice")
    with _connect(client) as ws:
        for i in range(ws_module._MAX_REJECTED_SUBSCRIBES):
            ws.send_json({"action": "subscribe", "topic": f"vehicle:PROBE{i}"})
            assert _rejection(ws)["topic"] == f"vehicle:PROBE{i}"
        with pytest.raises(WebSocketDisconnect) as closed:
            ws.receive_bytes()
        assert closed.value.code == 1008


def test_a_subscribe_for_a_topic_the_socket_already_holds_costs_no_lookup(client, db, monkeypatch):
    """A page re-sends its whole set on every reconnect; a topic this socket already
    holds is authorized once."""
    from app.routers import ws as ws_module

    user = _make_user(db, "alice")
    _make_vehicle(db, user, "CAR1")
    _login(client, "alice")
    calls = []
    original = ws_module._resolve_vehicle_topic

    def counting(topic, current_user):
        calls.append(topic)
        return original(topic, current_user)

    monkeypatch.setattr(ws_module, "_resolve_vehicle_topic", counting)
    with _connect(client) as ws:
        ws.send_json({"action": "subscribe", "topic": "vehicle:CAR1"})
        assert _wait_for_topics(["vehicle:CAR1"])
        ws.send_json({"action": "subscribe", "topic": "vehicle:CAR1"})
        ws.send_json({"action": "subscribe", "topic": "user:me"})
        assert _wait_for_topics([f"user:{user.id}"])
    assert calls == ["vehicle:CAR1"]


def test_a_rejected_topic_is_cut_before_it_is_echoed(client, db):
    _make_user(db, "alice")
    _login(client, "alice")
    with _connect(client) as ws:
        ws.send_json({"action": "subscribe", "topic": "vehicle:" + "x" * 5000})
        assert len(_rejection(ws)["topic"]) == 256


def test_a_message_that_is_not_a_subscription_still_closes_the_socket(client, db):
    user = _make_user(db)
    _make_vehicle(db, user, "CAR1")
    _login(client)
    with _connect(client) as ws:
        ws.send_json({"action": "subscribe", "topic": "vehicle:CAR1"})
        assert _wait_for_topics(["vehicle:CAR1"])
        ws.send_json({"action": "publish", "topic": "vehicle:CAR1"})
        with pytest.raises(WebSocketDisconnect):
            ws.receive_bytes()
    assert _wait_for_topics(["vehicle:CAR1"], present=False)


def test_a_frame_that_is_not_json_is_one_warning_and_a_1003_close(client, db, caplog):
    """
    Anything a client can send at will must not become an ERROR with a traceback per
    message: `receive_json` raised through the generic handler, and one line of junk
    was a stack trace in the log.
    """
    import logging
    _make_user(db)
    _login(client)
    caplog.set_level(logging.WARNING, logger="app.routers.ws")
    with _connect(client) as ws:
        ws.send_text("{not json")
        with pytest.raises(WebSocketDisconnect) as excinfo:
            ws.receive_bytes()
    assert excinfo.value.code == 1003
    records = [r for r in caplog.records if r.name == "app.routers.ws"]
    assert records and all(r.levelno == logging.WARNING and not r.exc_info for r in records)


def test_an_unexpected_message_is_cut_before_it_is_logged(client, db, caplog):
    import logging
    _make_user(db)
    _login(client)
    caplog.set_level(logging.WARNING, logger="app.routers.ws")
    with _connect(client) as ws:
        ws.send_json({"action": "publish", "topic": "x" * 100_000})
        with pytest.raises(WebSocketDisconnect):
            ws.receive_bytes()
    assert all(len(r.getMessage()) < 1000 for r in caplog.records if r.name == "app.routers.ws")


# ---------------------------------------------------------------------------
# the broadcaster
# ---------------------------------------------------------------------------

def _run_broadcaster_ticks(monkeypatch, db, setup, steps, interval=0.05):
    """
    Run periodic_vehicle_data_broadcaster with a fake broadcast, apply each step
    between ticks and return the topics sent after every step.
    """
    from app import lifespan
    from app.config import settings

    monkeypatch.setattr(settings, "WS_BROADCAST_INTERVAL_SECONDS", interval)
    sent = []

    async def fake_broadcast(topic, data):
        sent.append((topic, data["payload"]))

    monkeypatch.setattr(ws_manager, "broadcast_to_topic", fake_broadcast)

    async def scenario():
        stop = asyncio.Event()
        task = asyncio.create_task(lifespan.periodic_vehicle_data_broadcaster(stop))
        counts = []
        try:
            setup()
            await asyncio.sleep(interval * 6)
            counts.append(len(sent))
            for step in steps:
                step()
                await asyncio.sleep(interval * 6)
                counts.append(len(sent))
        finally:
            stop.set()
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            ws_manager.subscriptions.clear()
        return counts

    return asyncio.run(scenario()), sent


def test_the_broadcaster_sends_a_topic_only_when_its_payload_changed(monkeypatch, db):
    """
    A sleeping module produced the same frame for every tab every two seconds; a
    dashboard of 90 vehicles was 90 packed sends per tick with nothing new in any of
    them. The tick still runs (so a change is seen within one interval), but a topic
    whose payload is byte-identical to the last one sent is skipped — unless a
    subscriber joined since, who needs the current frame.
    """
    user = _make_user(db)
    _make_vehicle(db, user, "CAR1")

    def subscribed():
        ws_manager.subscriptions["vehicle:CAR1"] = {"tab1"}

    def joined():
        ws_manager.subscriptions["vehicle:CAR1"].add("tab2")

    def changed():
        metrics_manager.update_metric("CAR1", "v.b.soc", "77")

    counts, sent = _run_broadcaster_ticks(monkeypatch, db, subscribed, [joined, changed])

    # six ticks with one subscriber: one send; a second subscriber: one more; a
    # changed metric: one more — never one per tick.
    assert counts == [1, 2, 3], counts
    assert sent[-1][1]["v3_metrics"]["v.b.soc"] == "77"


def test_one_vehicle_the_parser_cannot_digest_does_not_stop_the_tick(monkeypatch, db, caplog):
    """
    All payloads of a tick are built in one threadpool hop. Unguarded, one stored
    message the parser cannot digest raised out of that hop and no vehicle on the
    server was sent — every dashboard froze on one bad row, where the old per-topic
    loop lost one card. The bad vehicle is skipped with an error; the rest goes out.
    """
    from app import lifespan

    user = _make_user(db)
    _make_vehicle(db, user, "CAR1")
    _make_vehicle(db, user, "CAR2")
    original = lifespan.build_vehicle_live_payload

    def failing_for_car2(vehicle_db):
        if vehicle_db.vehicle_id == "CAR2":
            raise ValueError("cannot parse this one")
        return original(vehicle_db)

    monkeypatch.setattr(lifespan, "build_vehicle_live_payload", failing_for_car2)

    def subscribed():
        ws_manager.subscriptions["vehicle:CAR1"] = {"tab1"}
        ws_manager.subscriptions["vehicle:CAR2"] = {"tab1"}

    with caplog.at_level("ERROR", logger="app.lifespan"):
        counts, sent = _run_broadcaster_ticks(monkeypatch, db, subscribed, [])

    assert counts == [1], counts
    assert [topic for topic, _ in sent] == ["vehicle:CAR1"]
    assert any("live payload of CAR2" in r.getMessage() for r in caplog.records)


def test_the_broadcaster_forgets_a_topic_nobody_watches(monkeypatch, db):
    """A topic that lost its last subscriber and comes back is sent again at once."""
    user = _make_user(db)
    _make_vehicle(db, user, "CAR1")

    def subscribed():
        ws_manager.subscriptions["vehicle:CAR1"] = {"tab1"}

    def gone():
        ws_manager.subscriptions.clear()

    def back():
        ws_manager.subscriptions["vehicle:CAR1"] = {"tab1"}

    counts, _ = _run_broadcaster_ticks(monkeypatch, db, subscribed, [gone, back])
    assert counts == [1, 1, 2], counts


@pytest.mark.parametrize(
    "stored",
    [
        datetime.datetime(2026, 3, 4, 5, 6, 7),  # noqa: DTZ001 — SQLite reads back naive
        datetime.datetime(2026, 3, 4, 5, 6, 7, tzinfo=datetime.timezone.utc),     # PostgreSQL: aware
        datetime.datetime(2026, 3, 4, 7, 6, 7, tzinfo=datetime.timezone(datetime.timedelta(hours=2))),
    ],
)
def test_last_message_at_is_a_z_string_on_every_backend(stored):
    assert as_utc_iso(stored) == "2026-03-04T05:06:07Z"


def test_last_message_at_none_stays_null():
    assert as_utc_iso(None) is None


def test_an_unsubscribe_never_touches_another_clients_subscription(client, db):
    user = _make_user(db)
    _make_vehicle(db, user, "CAR1")
    _login(client)

    with _connect(client) as first:
        first.send_json({"action": "subscribe", "topic": "vehicle:CAR1"})
        assert _wait_for_topics(["vehicle:CAR1"])
        with _connect(client) as second:
            second.send_json({"action": "unsubscribe", "topic": "vehicle:CAR1"})
            second.send_json({"action": "subscribe", "topic": "user:me"})
            assert _wait_for_topics([f"user:{user.id}"])
            assert "vehicle:CAR1" in ws_manager.subscriptions, "the first socket lost its topic"
