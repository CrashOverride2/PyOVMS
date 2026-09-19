"""
Vehicle notifications reach the owner's open browser tabs.

The dispatcher runs on worker threads; the sockets live on the event loop. What is
pinned here is the crossing between the two and the one rule of the `user:` topic:

  * `broadcast_threadsafe()` never blocks and never raises — without a bound loop it is
    a no-op, from a worker thread it delivers the msgpack envelope;
  * the payload is built from what the protocol handlers already put into the push
    payload, so the toast can name the subtype without a third parser;
  * **the frame is tagged `user:me`, the name the page subscribed with.** The manager
    routes on `user:<id>`, and the envelope used to carry that key: every notification
    reached the socket and was dropped by the page, which keys its handlers on the
    topic string it asked for and had never heard of `user:42`. The feature did not
    work, the server tests pinned the routing key and nothing spanned both ends —
    `test_a_subscribed_tab_receives_the_frame_under_the_name_it_subscribed_with`
    does now, and `test_web_notification_toasts_in_the_page.py` runs the page's own
    script against that frame;
  * `/ws` is authenticated by the session cookie — no ticket, no write — and refuses a
    handshake whose Origin is not this server (cross-site WebSocket hijacking: the
    browser attaches the cookie to a handshake any site starts; SameSite=Lax is the
    first lock, this the second); it resolves `user:me` from that session and answers
    any other spelling with `subscribe_rejected` — there is no administrative reading
    of another person's notifications, and no second name for one's own;
  * every authenticated page carries the socket script and the toast API, the
    anonymous ones only the API (the login page renders flash toasts), and the profile
    page carries the opt-in for native notifications without an inline handler.
"""

import asyncio
import re
import threading
import time

import msgpack
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect, WebSocketState

from app import security
from app.database import Base, SessionLocal, engine, get_db
from app.main import app
from app.models import db as models_db
from app.notifications import web as web_notifications
from app.routers.ws import origin_is_ours, resolve_user_topic
from app.security_manager import security_manager
from app.websocket_manager import WebSocketConnectionManager, manager as ws_manager, user_topic

PASSWORD = "CorrectHorse1!Battery"


# ---------------------------------------------------------------------------
# the payload
# ---------------------------------------------------------------------------

def _build(**overrides):
    kwargs = {
        "vehicle_id": "CAR1", "title": "OVMS Alert: CAR1 (charge/done)", "body": "Charge complete",
        "alert_type_char": "A", "source_protocol": "v3", "subtype": "charge/done",
        "timestamp": "2026-09-17T10:11:12+00:00",
    }
    kwargs.update(overrides)
    return web_notifications.build_web_notification(**kwargs)


def test_the_payload_has_exactly_the_fields_the_page_reads():
    payload = _build()
    assert set(payload) == {"id", "vehicle_id", "title", "body", "severity", "subtype", "source_protocol", "timestamp"}
    assert payload["severity"] == "alert"
    assert payload["subtype"] == "charge/done"


def test_two_payloads_never_share_an_id():
    """The id is what lets several open tabs collapse one notification into one."""
    assert _build()["id"] != _build()["id"]


@pytest.mark.parametrize(
    "char, severity",
    [("I", "info"), ("W", "warn"), ("A", "alert"), ("E", "error"), ("F", "info"),
     ("a", "alert"), ("x", "info"), ("", "info"), (None, "info")],
)
def test_severity_follows_the_alert_type_character(char, severity):
    assert web_notifications.severity_for(char) == severity


# ---------------------------------------------------------------------------
# notify_owner_browser
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_manager(monkeypatch):
    calls = []

    def broadcast_threadsafe(topic, data):
        calls.append((topic, data))
        return True

    monkeypatch.setattr(web_notifications.websocket_manager, "broadcast_threadsafe", broadcast_threadsafe)
    return calls


def _notify(**overrides):
    kwargs = {
        "vehicle_id": "CAR1", "title": "t", "body": "b", "alert_type_char": "I",
        "source_protocol": "v3", "fcm_data_payload": None, "timestamp": "2026-09-17T10:11:12+00:00",
    }
    kwargs.update(overrides)
    return web_notifications.notify_owner_browser(kwargs.pop("owner_id", 42), **kwargs)


def test_the_owner_topic_carries_a_notification_envelope(fake_manager):
    """Routed on the owner's key; tagged with the one name the page knows it by."""
    assert _notify() is True
    (topic, data), = fake_manager
    assert topic == "user:42"
    assert data["topic"] == "user:me"
    assert data["type"] == "notification"
    assert data["payload"]["vehicle_id"] == "CAR1"


@pytest.mark.parametrize(
    "push_payload, subtype",
    [({"v3_subtype": "charge/done"}, "charge/done"),
     ({"notification_id": "alarm.sounding"}, "alarm.sounding"),
     ({"v3_subtype": "a", "notification_id": "b"}, "a"),
     ({}, ""), (None, "")],
)
def test_the_subtype_is_taken_from_the_push_payload(fake_manager, push_payload, subtype):
    _notify(fcm_data_payload=push_payload)
    assert fake_manager[0][1]["payload"]["subtype"] == subtype


def test_no_owner_means_nothing_is_scheduled(fake_manager):
    assert _notify(owner_id=None) is False
    assert fake_manager == []


def test_a_failing_manager_never_reaches_the_dispatcher(monkeypatch):
    def broadcast_threadsafe(topic, data):
        raise RuntimeError("boom")

    monkeypatch.setattr(web_notifications.websocket_manager, "broadcast_threadsafe", broadcast_threadsafe)
    assert _notify() is False


# ---------------------------------------------------------------------------
# the thread -> loop bridge
# ---------------------------------------------------------------------------

class FakeWebSocket:
    def __init__(self):
        self.application_state = WebSocketState.CONNECTED
        self.client_state = WebSocketState.CONNECTED
        self.sent = []

    async def accept(self):
        pass

    async def close(self, code: int = 1000, reason: str | None = None):
        pass

    async def send_bytes(self, data: bytes):
        self.sent.append(data)


def test_broadcast_threadsafe_is_a_no_op_without_a_loop():
    manager = WebSocketConnectionManager()
    manager.subscriptions["user:7"] = {"alice_1"}
    result = []
    thread = threading.Thread(target=lambda: result.append(manager.broadcast_threadsafe("user:7", {"x": 1})))
    thread.start()
    thread.join(5)
    assert result == [False]


def test_broadcast_threadsafe_ignores_a_closed_loop():
    manager = WebSocketConnectionManager()
    manager.subscriptions["user:7"] = {"alice_1"}
    loop = asyncio.new_event_loop()
    loop.close()
    manager.bind_loop(loop)
    assert manager.broadcast_threadsafe("user:7", {"x": 1}) is False


def test_broadcast_threadsafe_delivers_from_a_worker_thread():
    async def scenario():
        manager = WebSocketConnectionManager()
        manager.bind_loop(asyncio.get_running_loop())
        ws = FakeWebSocket()
        await manager.connect(ws, "alice_1")
        await manager.subscribe("alice_1", "user:7")
        envelope = {"topic": "user:7", "type": "notification", "payload": {"id": "abc"}}

        results = []
        thread = threading.Thread(target=lambda: results.append(manager.broadcast_threadsafe("user:7", envelope)))
        thread.start()
        await asyncio.to_thread(thread.join, 5)
        assert results == [True]

        for _ in range(100):
            if ws.sent:
                break
            await asyncio.sleep(0.01)
        assert msgpack.unpackb(ws.sent[0], raw=False) == envelope

        # Nobody on that topic: nothing is scheduled, and the answer says so.
        assert manager.broadcast_threadsafe("user:8", envelope) is False
        manager.unbind_loop()

    asyncio.run(scenario())


def test_a_failing_broadcast_is_logged_not_swallowed(caplog):
    """
    Nobody awaits the future run_coroutine_threadsafe() hands back, so an exception in
    the broadcast used to be stored on it and seen by no one.
    """
    async def scenario():
        manager = WebSocketConnectionManager()
        manager.bind_loop(asyncio.get_running_loop())
        ws = FakeWebSocket()
        await manager.connect(ws, "alice_1")
        await manager.subscribe("alice_1", "user:7")

        # A payload msgpack cannot pack.
        unpackable = {"topic": "user:7", "payload": {"when": object()}}
        assert manager.broadcast_threadsafe("user:7", unpackable) is True
        for _ in range(100):
            if any("Broadcast to 'user:7' failed" in r.getMessage() for r in caplog.records):
                break
            await asyncio.sleep(0.01)
        manager.unbind_loop()

    with caplog.at_level("WARNING", logger="app.websocket_manager"):
        asyncio.run(scenario())
    assert any("Broadcast to 'user:7' failed" in r.getMessage() for r in caplog.records)


# ---------------------------------------------------------------------------
# the user topic
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "requested, expected",
    [("user:me", "user:7"), ("user:7", None), ("user:8", None), ("user:", None),
     ("user:me:x", None), ("vehicle:X", None), ("", None)],
)
def test_the_user_topic_is_always_the_callers_own(requested, expected):
    """
    One spelling. The frame on this topic is tagged `user:me`, so a subscription under
    the caller's own numeric id (accepted "harmlessly" once) would receive frames it
    can never match.
    """
    assert resolve_user_topic(requested, 7) == expected


# ---------------------------------------------------------------------------
# /ws and the pages, over HTTP
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
    def _get_db():
        session = SessionLocal()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = _get_db
    yield TestClient(app, base_url="https://testserver")
    app.dependency_overrides.clear()


def _make_user(db, username="alice"):
    user = models_db.User(
        username=username, email=f"{username}@example.com",
        hashed_password=security.get_password_hash(PASSWORD),
        is_active=True, is_admin=False, is_totp_enabled=False,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


ORIGIN = {"origin": "https://testserver"}


def _connect(client, **kwargs):
    """
    A handshake as the browser sends it: the session cookie and our own Origin.

    Starlette's TestClient does not attach its cookie jar to websocket_connect(), so
    the jar is spelled out as a Cookie header — a real browser does this on its own.
    """
    headers = {**ORIGIN}
    jar = "; ".join(f"{name}={value}" for name, value in client.cookies.items())
    if jar:
        headers["cookie"] = jar
    headers.update(kwargs.pop("headers", {}))
    return client.websocket_connect("/ws", headers=headers, **kwargs)


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


def _wait_for_topic(topic, present=True, timeout=2.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if (topic in ws_manager.subscriptions) is present:
            return True
        time.sleep(0.02)
    return (topic in ws_manager.subscriptions) is present


def test_user_me_subscribes_to_the_callers_own_topic(client, db):
    user = _make_user(db)
    _login(client)
    topic = user_topic(user.id)
    keys_before = db.query(models_db.ApiKey).count()

    with _connect(client) as ws:
        ws.send_json({"action": "subscribe", "topic": "user:me"})
        assert _wait_for_topic(topic), "the user topic never appeared"

    assert _wait_for_topic(topic, present=False), "the subscription outlived the socket"
    assert db.query(models_db.ApiKey).count() == keys_before, "a socket must not write an API key row"


def test_a_subscribed_tab_receives_the_frame_under_the_name_it_subscribed_with(client, db, monkeypatch):
    """
    The whole path, over HTTP: `user:me` on the socket, `notify_owner_browser()` from
    the dispatcher's thread, and the frame that arrives is tagged `user:me` — the
    string the page keys its handlers on. It was tagged with the routing key, and no
    test read the frame off the socket.

    The TestClient runs no lifespan, so the loop the socket lives on is bound where
    lifespan() would have bound it: on the way through `connect()`, which runs on it.
    """
    user = _make_user(db)
    _login(client)
    original_connect = ws_manager.connect

    async def connect_and_bind_loop(*args, **kwargs):
        ws_manager.bind_loop(asyncio.get_running_loop())
        return await original_connect(*args, **kwargs)

    monkeypatch.setattr(ws_manager, "connect", connect_and_bind_loop)
    try:
        with _connect(client) as ws:
            ws.send_json({"action": "subscribe", "topic": "user:me"})
            assert _wait_for_topic(user_topic(user.id))
            assert web_notifications.notify_owner_browser(
                user.id, vehicle_id="CAR1", title="OVMS Alert: CAR1 (charge/done)",
                body="Charge complete", alert_type_char="A", source_protocol="v3",
                fcm_data_payload={"v3_subtype": "charge/done"}, timestamp="2026-09-17T10:11:12+00:00",
            ) is True
            frame = msgpack.unpackb(ws.receive_bytes(), raw=False)
    finally:
        ws_manager.unbind_loop()

    assert frame["topic"] == "user:me"
    assert frame["type"] == "notification"
    assert frame["payload"]["vehicle_id"] == "CAR1"
    assert frame["payload"]["body"] == "Charge complete"
    assert frame["payload"]["severity"] == "alert"
    assert frame["payload"]["subtype"] == "charge/done"


def test_the_callers_own_numeric_id_is_no_second_name_for_the_topic(client, db):
    """Accepted once; a subscription that can never match a frame is refused now."""
    user = _make_user(db)
    _login(client)

    with _connect(client) as ws:
        ws.send_json({"action": "subscribe", "topic": user_topic(user.id)})
        answer = msgpack.unpackb(ws.receive_bytes(), raw=False)
        assert answer == {"type": "subscribe_rejected", "topic": user_topic(user.id)}
        assert user_topic(user.id) not in ws_manager.subscriptions


def test_unsubscribing_user_me_removes_the_subscription_it_made(client, db):
    user = _make_user(db)
    _login(client)

    with _connect(client) as ws:
        ws.send_json({"action": "subscribe", "topic": "user:me"})
        assert _wait_for_topic(user_topic(user.id))
        ws.send_json({"action": "unsubscribe", "topic": "user:me"})
        assert _wait_for_topic(user_topic(user.id), present=False), "the alias was not resolved on unsubscribe"


def test_another_users_topic_is_rejected_and_nothing_is_subscribed(client, db):
    alice = _make_user(db, "alice")
    bob = _make_user(db, "bob")
    _login(client, "alice")

    with _connect(client) as ws:
        ws.send_json({"action": "subscribe", "topic": user_topic(bob.id)})
        answer = msgpack.unpackb(ws.receive_bytes(), raw=False)
        assert answer == {"type": "subscribe_rejected", "topic": user_topic(bob.id)}
        assert user_topic(bob.id) not in ws_manager.subscriptions
        assert user_topic(alice.id) not in ws_manager.subscriptions


def test_a_vehicle_page_socket_needs_no_ticket_either(client, db):
    user = _make_user(db)
    vehicle = models_db.Vehicle(vehicle_id="CAR1", owner_id=user.id, protocol="both",
                                encrypted_server_password=b"x")
    db.add(vehicle)
    db.commit()
    _login(client)

    with _connect(client) as ws:
        ws.send_json({"action": "subscribe", "topic": "vehicle:CAR1"})
        assert _wait_for_topic("vehicle:CAR1")

    assert _wait_for_topic("vehicle:CAR1", present=False)


def test_the_ticket_endpoint_is_gone(client, db):
    _make_user(db)
    _login(client)
    assert client.get("/api/v1/ws-ticket").status_code == 404


def _refused(client, **kwargs):
    """
    The handshake is accepted and then closed with 1008. A close *before* the accept
    is an HTTP 403 from uvicorn, which the browser reports as 1006 — the same code as
    any dropped connection — so the page could never tell a refusal from an outage
    and its "three refusals and stop" guard never fired. The TestClient reports 1008
    either way; what tells the two apart here is whether `__enter__` returned.
    """
    accepted = False
    with pytest.raises(WebSocketDisconnect) as excinfo:
        with _connect(client, **kwargs) as ws:
            accepted = True
            ws.receive_bytes()
    assert accepted, "refused before accept(): the browser sees 1006, not 1008"
    assert excinfo.value.code == 1008


def test_no_session_no_socket(client, db):
    _make_user(db)
    _refused(client)


def test_a_session_parked_on_the_totp_page_gets_no_socket(client, db):
    """MFA is enforced exactly as on every page: a cookie without the claim is not a session."""
    user = _make_user(db)
    user.is_totp_enabled = True
    db.commit()
    # What the login form issues before the TOTP step: a valid token with mfa=False.
    token = security.create_access_token_with_2fa_status(
        username=user.username, is_2fa_completed=False, token_version=user.token_version or 0)
    _refused(client, headers={"cookie": f"__Host-access_token={token}"})


def test_a_foreign_origin_is_refused_even_with_a_valid_cookie(client, db):
    """
    Cross-site WebSocket hijacking: a page on another site opens our socket, and the
    browser attaches the cookie. SameSite=Lax stops it; this is the second lock.
    """
    _make_user(db)
    _login(client)
    _refused(client, headers={"origin": "https://evil.example"})


def test_a_handshake_without_an_origin_is_refused(client, db):
    _make_user(db)
    _login(client)
    jar = "; ".join(f"{name}={value}" for name, value in client.cookies.items())
    accepted = False
    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect("/ws", headers={"cookie": jar}) as ws:
            accepted = True
            ws.receive_bytes()
    assert accepted
    assert excinfo.value.code == 1008


@pytest.mark.parametrize(
    "origin, host, expected",
    [
        ("https://ovms.example", "ovms.example", True),
        ("https://OVMS.example", "ovms.example", True),
        ("https://ovms.example:8443", "ovms.example:8443", True),
        ("https://ovms.example:8443", "ovms.example", False),
        ("https://evil.example", "ovms.example", False),
        ("null", "ovms.example", False),
        ("", "ovms.example", False),
        (None, "ovms.example", False),
        ("https://ovms.example", None, False),
        ("https://ovms.example", "", False),
        # A proxy that rewrites Host to the upstream: the configured origin still counts.
        ("http://localhost:8000", "127.0.0.1:8000", True),
    ],
)
def test_origin_is_ours(origin, host, expected):
    assert origin_is_ours(origin, host) is expected


@pytest.mark.parametrize(
    "origin, secure, expected",
    [
        # Over TLS the page must be https: a plain-http page on the same name gets
        # the cookie's socket otherwise (cookies follow the target, not the page).
        ("https://ovms.example", True, True),
        ("http://ovms.example", True, False),
        ("HTTPS://ovms.example", True, True),
        # A plain-http deployment (local test server) keeps its http pages.
        ("http://ovms.example", False, True),
    ],
)
def test_origin_scheme_must_match_a_tls_handshake(origin, secure, expected):
    assert origin_is_ours(origin, "ovms.example", secure=secure) is expected


def test_every_authenticated_page_carries_the_socket_and_the_toast_api(client, db):
    _make_user(db)
    _login(client)

    page = client.get("/dashboard")
    assert page.status_code == 200, page.text[:500]
    assert "window.ovmsToast" in page.text
    assert "window.ovmsNativeNotifications" in page.text
    assert "user:me" in page.text
    assert "ws-ticket" not in page.text
    # The CSP allows no inline script without a nonce: every inline block must carry
    # one (external `src` scripts are covered by 'self').
    assert re.search(r"<script(?![^>]*\b(?:nonce|src)=)[^>]*>", page.text) is None


def test_the_anonymous_page_has_the_toast_api_but_no_socket(client):
    page = client.get("/login")
    assert page.status_code == 200
    assert "window.ovmsToast" in page.text
    assert "user:me" not in page.text


def _container(page_text: str, element_id: str) -> str:
    """The markup of one fixed toast container, opening tag to the next `<div id=`/`<main`."""
    match = re.search(rf'<div id="{element_id}"(.*?)(?=<div id=|<main)', page_text, re.S)
    assert match is not None, f"base.html no longer carries #{element_id}"
    return match.group(0)


def test_a_flash_message_pops_up_in_the_middle_not_in_the_corner(client):
    """
    The server's own messages ("deleted", "please log in") answer what the person
    just did and are rendered into the centred #ovms-flash container. The corner
    container, #ovms-toasts, is reserved for vehicle notifications and is served
    empty: a flash message there would look like something the car said.
    """
    page = client.get("/login?error_message=PROBE_FLASH_2b9c")
    assert page.status_code == 200
    flash = _container(page.text, "ovms-flash")
    corner = _container(page.text, "ovms-toasts")
    assert "PROBE_FLASH_2b9c" in flash and 'data-toast-kind="error"' in flash
    assert "PROBE_FLASH_2b9c" not in corner and "ovms-toast " not in corner
    # centred: vertically by top-1/2 with the -50% translate, horizontally by the
    # auto margins; the corner keeps its bottom-right anchor
    assert "top-1/2" in flash and "-translate-y-1/2" in flash and "sm:mx-auto" in flash
    assert "bottom-4" in corner and "sm:left-auto" in corner


def test_the_profile_page_offers_the_native_opt_in_without_inline_handlers(client, db):
    _make_user(db)
    _login(client)

    page = client.get("/profile")
    assert page.status_code == 200, page.text[:500]
    assert 'id="native-notifications-enable"' in page.text
    assert 'id="native-notifications-disable"' in page.text
    assert "onclick=" not in page.text
