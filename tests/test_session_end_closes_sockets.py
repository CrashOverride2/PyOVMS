"""
A WebSocket does not outlive the session it was opened with.

The socket is authenticated once, at the handshake, and the cookie is never looked
at again. Two things end a session before the tab is closed, and both used to leave
the socket streaming live data to a page with no session behind it:

  * a logout — in another tab of the same browser, which deletes the cookie for all
    of them. The logout route closes the account's sockets in this worker
    (`disconnect_user`, code 1008, so the page counts it as a refusal);
  * the token's expiry. The endpoint carries the `exp` claim along and closes the
    socket when it passes, with the same code.

The page then reconnects, is refused, and after three refusals asks the server about
itself; a redirect (to the login page) reloads it there.
"""

import asyncio
import datetime
import re
import threading
import time

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect, WebSocketState

from app import security
from app.database import Base, SessionLocal, engine, get_db
from app.main import app
from app.models import db as models_db
from app.routers.ui import auth as ui_auth
from app.security_manager import security_manager
from app.websocket_manager import WebSocketConnectionManager

PASSWORD = "CorrectHorse1!Battery"


class FakeWebSocket:
    def __init__(self):
        self.application_state = WebSocketState.CONNECTED
        self.client_state = WebSocketState.CONNECTED
        self.closed_with = None

    async def accept(self):
        pass

    async def close(self, code: int = 1000, reason: str | None = None):
        self.closed_with = code
        self.application_state = WebSocketState.DISCONNECTED


# ---------------------------------------------------------------------------
# the manager
# ---------------------------------------------------------------------------

def test_disconnect_user_closes_every_socket_of_that_account_and_no_other():
    async def scenario():
        manager = WebSocketConnectionManager()
        alice_tab1, alice_tab2, bob = FakeWebSocket(), FakeWebSocket(), FakeWebSocket()
        await manager.connect(alice_tab1, "alice_1", user_id=1)
        await manager.connect(alice_tab2, "alice_2", user_id=1)
        await manager.connect(bob, "bob_1", user_id=2)
        await manager.subscribe("alice_1", "vehicle:CAR1")
        await manager.subscribe("alice_2", "user:1")
        await manager.subscribe("bob_1", "vehicle:CAR1")

        closed = await manager.disconnect_user(1)

        assert closed == 2
        assert alice_tab1.closed_with == 1008 and alice_tab2.closed_with == 1008
        assert bob.closed_with is None
        assert set(manager.active_connections) == {"bob_1"}
        assert manager.connection_users == {"bob_1": 2}
        # Alice's subscriptions went with her sockets; Bob's stayed.
        assert manager.subscriptions == {"vehicle:CAR1": {"bob_1"}}

    asyncio.run(scenario())


def test_disconnect_user_with_no_sockets_is_nothing():
    async def scenario():
        manager = WebSocketConnectionManager()
        assert await manager.disconnect_user(42) == 0
    asyncio.run(scenario())


def test_disconnect_user_threadsafe_is_a_no_op_without_a_loop():
    manager = WebSocketConnectionManager()
    manager.connection_users["alice_1"] = 1
    assert manager.disconnect_user_threadsafe(1) is False


def test_disconnect_user_threadsafe_closes_from_a_request_thread():
    """The logout route runs on a worker thread; the sockets live on the loop."""
    async def scenario():
        manager = WebSocketConnectionManager()
        manager.bind_loop(asyncio.get_running_loop())
        ws = FakeWebSocket()
        await manager.connect(ws, "alice_1", user_id=1)

        results = []
        worker = threading.Thread(target=lambda: results.append(manager.disconnect_user_threadsafe(1)))
        worker.start()
        worker.join(timeout=2)

        for _ in range(100):
            if ws.closed_with is not None:
                break
            await asyncio.sleep(0.01)
        assert results == [True]
        assert ws.closed_with == 1008
        assert "alice_1" not in manager.active_connections

    asyncio.run(scenario())


# ---------------------------------------------------------------------------
# over HTTP
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
    db.query(models_db.SecurityEvent).delete()
    db.query(models_db.User).delete()
    db.commit()
    security_manager.blocked_ips.clear()
    security_manager.failed_attempts.clear()
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


def test_the_socket_closes_with_1008_when_the_token_expires(client, db):
    user = _make_user(db)
    token = security.create_access_token_with_2fa_status(
        username=user.username, is_2fa_completed=True,
        expires_delta=datetime.timedelta(seconds=1), token_version=user.token_version or 0,
    )
    headers = {"origin": "https://testserver", "cookie": f"__Host-access_token={token}"}
    started = time.monotonic()
    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect("/ws", headers=headers) as ws:
            ws.send_json({"action": "subscribe", "topic": "user:me"})
            ws.receive_bytes()
    assert excinfo.value.code == 1008
    assert time.monotonic() - started < 5


def test_logout_closes_the_sockets_of_that_account(client, db, monkeypatch):
    """
    The TestClient runs no lifespan, so no loop is bound and the manager's
    thread-safe call would be a no-op; what is pinned is that the logout route makes
    it, for the user who logged out.
    """
    user = _make_user(db)
    calls = []
    monkeypatch.setattr(ui_auth.websocket_manager, "disconnect_user_threadsafe", lambda uid: calls.append(uid) or True)
    _login(client)

    response = client.get("/logout", follow_redirects=False)

    assert response.status_code in (302, 303, 307)
    assert calls == [user.id]
