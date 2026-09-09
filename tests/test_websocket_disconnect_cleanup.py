"""
A disconnecting client must always leave the subscription table clean.

The bug this pins down was invisible except as log noise. Closing a socket whose peer has
already gone raises — uvicorn signals ClientDisconnected, starlette re-raises it as
WebSocketDisconnect(1006) — and the manager only caught RuntimeError. So the *ordinary*
end of a connection (closed tab, phone off the network) escaped from disconnect(), which
skipped the subscription cleanup that stood below the close and propagated out of the ASGI
app as a full traceback. The stale client id kept its topic non-empty forever, and the
broadcaster in lifespan.py went on querying the database and packing a payload for that
vehicle every 2 seconds with nobody left to receive it.
"""

import asyncio

import pytest
from starlette.websockets import WebSocketDisconnect, WebSocketState

from app.websocket_manager import WebSocketConnectionManager


class FakeWebSocket:
    """A connected socket whose close() fails the way a vanished peer's does."""

    def __init__(self, close_error: BaseException | None = None):
        self.application_state = WebSocketState.CONNECTED
        self.client_state = WebSocketState.CONNECTED
        self.close_error = close_error
        self.close_calls = 0
        self.accepted = False

    async def accept(self):
        self.accepted = True

    async def close(self, code: int = 1000, reason: str | None = None):
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error


async def _connected_manager(ws: FakeWebSocket) -> WebSocketConnectionManager:
    manager = WebSocketConnectionManager()
    await manager.connect(ws, "user_abcd1234")
    await manager.subscribe("user_abcd1234", "vehicle:ZOE90")
    return manager


@pytest.mark.parametrize(
    "close_error",
    [
        WebSocketDisconnect(code=1006),
        RuntimeError('Cannot call "send" once a close message has been sent.'),
        OSError("connection reset by peer"),
    ],
    ids=["client_gone", "already_closed", "transport_error"],
)
def test_disconnect_cleans_up_even_when_closing_fails(close_error):
    async def scenario():
        ws = FakeWebSocket(close_error=close_error)
        manager = await _connected_manager(ws)

        # Must not raise: the endpoint calls this from its `finally`, so anything that
        # escapes here leaves uvicorn logging an unhandled exception per disconnect.
        await manager.disconnect("user_abcd1234")

        assert manager.active_connections == {}
        # The topic itself is gone, not merely emptied — that is what stops the
        # broadcaster from building an update nobody is subscribed to.
        assert manager.subscriptions == {}

    asyncio.run(scenario())


def test_disconnect_does_not_close_a_socket_the_client_already_left():
    """The quiet path: no send is attempted once the peer has said goodbye."""

    async def scenario():
        ws = FakeWebSocket()
        manager = await _connected_manager(ws)
        # What starlette leaves behind after receive() raises WebSocketDisconnect.
        ws.client_state = WebSocketState.DISCONNECTED

        await manager.disconnect("user_abcd1234")

        assert ws.close_calls == 0
        assert manager.subscriptions == {}

    asyncio.run(scenario())


def test_disconnect_closes_a_still_live_socket():
    async def scenario():
        ws = FakeWebSocket()
        manager = await _connected_manager(ws)

        await manager.disconnect("user_abcd1234")

        assert ws.close_calls == 1

    asyncio.run(scenario())


def test_disconnecting_twice_is_harmless():
    """
    broadcast_to_topic() reaps a client whose send failed, and the endpoint's `finally`
    reaps the same client a moment later.
    """

    async def scenario():
        ws = FakeWebSocket(close_error=WebSocketDisconnect(code=1006))
        manager = await _connected_manager(ws)

        await manager.disconnect("user_abcd1234")
        await manager.disconnect("user_abcd1234")

        assert manager.active_connections == {}
        assert manager.subscriptions == {}

    asyncio.run(scenario())


def test_other_subscribers_of_the_same_topic_survive():
    async def scenario():
        manager = WebSocketConnectionManager()
        leaving = FakeWebSocket(close_error=WebSocketDisconnect(code=1006))
        staying = FakeWebSocket()
        await manager.connect(leaving, "leaving_1")
        await manager.connect(staying, "staying_2")
        await manager.subscribe("leaving_1", "vehicle:ZOE90")
        await manager.subscribe("staying_2", "vehicle:ZOE90")

        await manager.disconnect("leaving_1")

        assert manager.subscriptions == {"vehicle:ZOE90": {"staying_2"}}
        assert set(manager.active_connections) == {"staying_2"}

    asyncio.run(scenario())


def test_a_failed_broadcast_reaps_the_dead_subscriber():
    """
    The same leak reached through broadcast_to_topic(): its reaper calls disconnect(),
    which used to raise on exactly the connections it was called for.
    """

    async def scenario():
        manager = WebSocketConnectionManager()

        class DeadWebSocket(FakeWebSocket):
            async def send_bytes(self, data: bytes):
                raise WebSocketDisconnect(code=1006)

        ws = DeadWebSocket(close_error=WebSocketDisconnect(code=1006))
        await manager.connect(ws, "user_abcd1234")
        await manager.subscribe("user_abcd1234", "vehicle:ZOE90")

        await manager.broadcast_to_topic("vehicle:ZOE90", {"topic": "vehicle:ZOE90", "payload": {}})

        assert manager.active_connections == {}
        assert manager.subscriptions == {}

    asyncio.run(scenario())
