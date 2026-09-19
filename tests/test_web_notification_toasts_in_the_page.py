"""
The page renders the frame the server sends — run as the page's own script.

`test_web_notification_toasts.py` proves that a subscribed socket receives a
`notification` frame tagged `user:me`. This runs the scripts of `base.html` as the
browser would — the toast API, the native-notification layer, `window.ovmsSocket`
and the `user:me` subscriber, rendered through the TestClient so every `url_for`
and translated label is in place — under node with a stub DOM and a stub WebSocket,
hands them that frame, and reads the toast off the container.

The bug this guards against lived between the two ends: the server tagged the frame
with its routing key `user:42`, the page keyed its handlers on the string it
subscribed with, and every notification was dropped unrendered. Each end passed its
own tests. The negative case below is the old frame, kept so the harness is shown
to tell the difference.

Skipped where node is not installed (CI has no JS toolchain).
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from app import security
from app.database import Base, SessionLocal, engine, get_db
from app.main import app
from app.models import db as models_db
from app.notifications import web as web_notifications
from app.security_manager import security_manager
from app.websocket_manager import USER_TOPIC_ALIAS
from fastapi.testclient import TestClient

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")

REPO_ROOT = Path(__file__).resolve().parent.parent
MSGPACK_JS = REPO_ROOT / "app" / "static" / "js" / "msgpack.min.js"
PASSWORD = "CorrectHorse1!Battery"

# The inline blocks of base.html this needs, by a line each one is known to carry.
PAGE_SCRIPT_MARKERS = (
    "window.ovmsToast = { show };",
    "window.ovmsNativeNotifications =",
    "window.ovmsSocket =",
    "window.ovmsSocket.subscribe('user:me'",
)

# What a browser gives the page and node does not. Timers never fire: a toast arms
# a 10 s dismiss, and the process must not wait for it.
HARNESS_PRELUDE = r"""
    const MessagePack = require(%(msgpack)s);
    class FakeElement {
        constructor(tag) {
            this.tagName = tag; this.children = []; this.dataset = {}; this.attributes = {};
            this.className = ''; this.textContent = ''; this.parentNode = null;
            this.classList = { add() {}, remove() {} };
        }
        appendChild(child) { child.parentNode = this; this.children.push(child); return child; }
        remove() { const p = this.parentNode; if (p) p.children.splice(p.children.indexOf(this), 1); }
        setAttribute(name, value) { this.attributes[name] = String(value); }
        addEventListener() {}
        querySelector() { return null; }
        querySelectorAll() { return []; }
        get firstElementChild() { return this.children[0] || null; }
    }
    const textOf = (node) => node.children && node.children.length ? node.children.map(textOf).join('') : String(node.textContent);
    // The two places a toast can land: the server's own messages in the middle of
    // the screen, a vehicle's notifications in the corner.
    const flash = new FakeElement('div');
    const container = new FakeElement('div');
    const noStorage = { getItem() { return null; }, setItem() {}, removeItem() {} };
    class FakeWebSocket {
        constructor(url) { this.url = String(url); this.readyState = FakeWebSocket.CONNECTING; this.sent = []; FakeWebSocket.instances.push(this); }
        send(message) { this.sent.push(JSON.parse(message)); }
        close() { this.readyState = FakeWebSocket.CLOSED; }
    }
    FakeWebSocket.CONNECTING = 0; FakeWebSocket.OPEN = 1; FakeWebSocket.CLOSING = 2; FakeWebSocket.CLOSED = 3;
    FakeWebSocket.instances = [];
    Object.assign(globalThis, {
        window: globalThis,
        document: {
            getElementById: (id) => (id === 'ovms-toasts' ? container : id === 'ovms-flash' ? flash : null),
            createElement: (tag) => new FakeElement(tag),
            createTextNode: (text) => ({ textContent: String(text), children: [] }),
            addEventListener() {},
            visibilityState: 'visible',
        },
        location: { protocol: 'https:', host: 'testserver', href: 'https://testserver/dashboard', pathname: '/dashboard' },
        localStorage: noStorage, sessionStorage: noStorage,
        WebSocket: FakeWebSocket, MessagePack,
        addEventListener() {},
        setTimeout: () => 0, clearTimeout: () => {},
        fetch: () => Promise.reject(new Error('no network in the harness')),
    });
"""

HARNESS_DRIVE = r"""
    const frame = %(frame)s;
    const socket = FakeWebSocket.instances[0];
    if (!socket) throw new Error('the page opened no socket');
    socket.readyState = FakeWebSocket.OPEN;
    socket.onopen();
    const bytes = MessagePack.encode(frame);
    socket.onmessage({ data: bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) });
    // A message of the server's own, as a page script would raise it after an AJAX
    // call: no placement named, so it takes the default.
    window.ovmsToast.show({ kind: 'success', heading: 'Success!', text: 'PROBE_SERVER_MESSAGE' });
    const describe = (toast) => ({ kind: toast.dataset.toastKind, sticky: 'toastSticky' in toast.dataset, text: textOf(toast) });
    console.log(JSON.stringify({
        socketUrl: socket.url,
        subscribed: socket.sent,
        toasts: container.children.map(describe),
        flash: flash.children.map(describe),
    }));
"""


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


def _login(client, db):
    user = models_db.User(
        username="alice", email="alice@example.com",
        hashed_password=security.get_password_hash(PASSWORD),
        is_active=True, is_admin=False, is_totp_enabled=False,
    )
    db.add(user)
    db.commit()
    page = client.get("/login")
    token = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', page.text) or \
        re.search(r'value="([^"]+)"[^>]*name="csrf_token"', page.text)
    assert token is not None
    response = client.post(
        "/login", data={"username": "alice", "password": PASSWORD, "csrf_token": token.group(1)},
        follow_redirects=False,
    )
    assert response.status_code in (302, 303, 307), response.text


def _page_scripts(client) -> str:
    """The four inline blocks, in page order, as the dashboard serves them."""
    page = client.get("/dashboard")
    assert page.status_code == 200, page.text[:500]
    blocks = re.findall(r'<script nonce="[^"]+">(.*?)</script>', page.text, re.S)
    chosen = [block for block in blocks if any(marker in block for marker in PAGE_SCRIPT_MARKERS)]
    missing = [m for m in PAGE_SCRIPT_MARKERS if not any(m in block for block in chosen)]
    assert not missing, f"base.html no longer carries: {missing}"
    return "\n".join(chosen)


def _server_frame(alert_type_char: str = "A", **overrides) -> dict:
    """The envelope `notify_owner_browser()` hands the manager, caught on its way."""
    captured = []
    original = web_notifications.websocket_manager.broadcast_threadsafe
    web_notifications.websocket_manager.broadcast_threadsafe = lambda topic, data: captured.append(data) or True
    try:
        web_notifications.notify_owner_browser(
            42, vehicle_id="CAR1", title="OVMS Alert: CAR1 (charge/done)", body="Charge complete",
            alert_type_char=alert_type_char, source_protocol="v3", fcm_data_payload={"v3_subtype": "charge/done"},
            timestamp="2026-09-17T10:11:12+00:00",
        )
    finally:
        web_notifications.websocket_manager.broadcast_threadsafe = original
    (frame,) = captured
    return {**frame, **overrides}


def _run_page(client, frame: dict) -> dict:
    script = (
        HARNESS_PRELUDE % {"msgpack": json.dumps(str(MSGPACK_JS))}
        + _page_scripts(client)
        + HARNESS_DRIVE % {"frame": json.dumps(frame)}
    )
    result = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize(
    "alert_type_char, kind, sticky",
    # An alert is red and stays until dismissed; an info note is blue and fades.
    [("A", "error", True), ("I", "info", False)],
)
def test_the_page_renders_the_servers_frame_as_a_toast(client, db, alert_type_char, kind, sticky):
    _login(client, db)
    frame = _server_frame(alert_type_char)
    assert frame["topic"] == USER_TOPIC_ALIAS

    out = _run_page(client, frame)

    assert out["socketUrl"] == "wss://testserver/ws"
    assert {"action": "subscribe", "topic": "user:me"} in out["subscribed"]
    assert len(out["toasts"]) == 1, out
    toast = out["toasts"][0]
    assert toast["kind"] == kind
    assert toast["sticky"] is sticky
    assert "CAR1" in toast["text"] and "charge/done" in toast["text"] and "Charge complete" in toast["text"]


def test_vehicle_notifications_take_the_corner_and_server_messages_the_middle(client, db):
    """
    Two places, by who is speaking. A vehicle's notification arrives unasked and
    goes to the corner container; a message of the server's own answers what the
    person just did and pops up in the middle — the default placement, so a page
    script that names none lands there. Neither container receives the other's.
    """
    _login(client, db)
    out = _run_page(client, _server_frame("I"))

    assert len(out["flash"]) == 1, out
    assert out["flash"][0]["kind"] == "success"
    assert "Success! PROBE_SERVER_MESSAGE" in out["flash"][0]["text"]
    assert len(out["toasts"]) == 1 and "CAR1" in out["toasts"][0]["text"], out
    assert not any("PROBE_SERVER_MESSAGE" in t["text"] for t in out["toasts"])


def test_a_frame_tagged_with_the_routing_key_reaches_no_handler(client, db):
    """
    The old frame. The page keys on the string it subscribed with, so this is
    delivered to the socket and rendered by nothing — which is why the server must
    tag the frame `user:me`, and why the test above is the one that matters.
    """
    _login(client, db)
    out = _run_page(client, _server_frame(topic="user:42"))
    assert out["toasts"] == []
    assert len(out["flash"]) == 1 and "PROBE_SERVER_MESSAGE" in out["flash"][0]["text"]
