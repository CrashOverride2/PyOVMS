import asyncio
import logging
from typing import Dict, FrozenSet, Optional, Set
from fastapi import WebSocket
from starlette.websockets import WebSocketState
import msgpack

from app.config import settings

logger = logging.getLogger(__name__)

VEHICLE_TOPIC_PREFIX = "vehicle:"
USER_TOPIC_PREFIX = "user:"
USER_TOPIC_ALIAS = f"{USER_TOPIC_PREFIX}me"


def user_topic(user_id: int) -> str:
    """The routing key of one person's topic; server-side only, never on the wire."""
    return f"{USER_TOPIC_PREFIX}{user_id}"


def vehicle_topic(vehicle_id: str) -> str:
    """The topic of one vehicle's live data — the string the page subscribes with."""
    return f"{VEHICLE_TOPIC_PREFIX}{vehicle_id}"


def _log_scheduled_failure(future, label: str) -> None:
    if future.cancelled():
        return
    exc = future.exception()
    if exc is not None:
        logger.warning(f"{label[:1].upper()}{label[1:]} failed: {exc!r}")


class WebSocketConnectionManager:
    """Manages active WebSocket connections and topic-based subscriptions."""

    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.subscriptions: Dict[str, Set[str]] = {}
        self.connection_users: Dict[str, int] = {}
        self._lock = asyncio.Lock()
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def bind_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Remember the event loop the sockets live on, for broadcast_threadsafe()."""
        self._loop = loop

    def unbind_loop(self) -> None:
        self._loop = None

    def _schedule(self, coro, label: str) -> bool:
        """
        Run a coroutine on the bound loop from any other thread and return at once.

        The one crossing point between worker threads and the sockets, which all belong
        to the loop. It never waits. True means scheduled, not done. Without a bound
        loop (tests, a TestClient without lifespan, after shutdown) it is a no-op.
        """
        loop = self._loop
        if loop is None or loop.is_closed():
            coro.close()
            logger.debug(f"No event loop bound; dropping {label}.")
            return False
        try:
            future = asyncio.run_coroutine_threadsafe(coro, loop)
        except RuntimeError as e:
            coro.close()
            logger.debug(f"Event loop unavailable; dropping {label}: {e}")
            return False
        future.add_done_callback(lambda f: _log_scheduled_failure(f, label))
        return True

    def broadcast_threadsafe(self, topic: str, data: dict) -> bool:
        """
        Hand a broadcast to the event loop from any other thread and return at once.

        The notification dispatcher runs on worker threads — the MQTT notify pool, an
        asyncio.to_thread() from the V2 handler, Starlette's background tasks — while
        every socket here belongs to the loop. Nothing may hold a dispatch worker on
        the browser's account, so this never waits: True means the send was scheduled,
        not that anyone received it. The unlocked membership check is deliberate: it
        is atomic under the GIL, the authoritative one runs under the lock inside
        broadcast_to_topic(), and it spares the loop hop in the common case that the
        owner has no tab open.
        """
        if topic not in self.subscriptions:
            return False
        return self._schedule(self.broadcast_to_topic(topic, data), f"broadcast to '{topic}'")

    def disconnect_user_threadsafe(self, user_id: int) -> bool:
        """
        Close every socket of one account, from a request thread; see disconnect_user().
        """
        if user_id not in self.connection_users.values():
            return False
        return self._schedule(self.disconnect_user(user_id), f"disconnect of user {user_id}")

    def drop_topic_threadsafe(self, topic: str) -> bool:
        """
        Withdraw a topic from every socket, from a request thread; see drop_topic().
        """
        if topic not in self.subscriptions:
            return False
        return self._schedule(self.drop_topic(topic), f"withdrawal of topic '{topic}'")

    async def drop_topic(self, topic: str) -> int:
        """
        Withdraw a topic from every socket that holds it and return how many did.

        A subscription is authorized once, when it is made. So when the vehicle behind
        a `vehicle:` topic is deleted, its subscribers kept the topic — and a vehicle
        registered later under the same id, by anyone, was streamed to the previous
        owner's open tab for as long as that tab's session lasted. The sockets stay
        open (the other cards of a dashboard are unaffected); each former subscriber
        is sent the same `subscribe_rejected` frame a refused subscribe earns, which
        is what makes the page drop the topic from its resubscribe set rather than
        ask for it again on every reconnect. A socket that cannot be told is reaped,
        as it would be by any broadcast.
        """
        async with self._lock:
            subscribers = self.subscriptions.pop(topic, None)
            sockets = [
                (client_id, self.active_connections[client_id])
                for client_id in (subscribers or ())
                if client_id in self.active_connections
            ]
        if not subscribers:
            return 0
        frame = msgpack.packb({"type": "subscribe_rejected", "topic": topic}, use_bin_type=True)
        for client_id, ws in sockets:
            try:
                await asyncio.wait_for(ws.send_bytes(frame), timeout=settings.WS_SEND_TIMEOUT_SECONDS)
            except Exception as e:
                logger.warning(f"Send error for client '{client_id}' on topic '{topic}': {e}. Marking for disconnect.")
                await self.disconnect(client_id)
        logger.info(f"Topic '{topic}' withdrawn from {len(subscribers)} client(s).")
        return len(subscribers)

    async def disconnect_user(self, user_id: int, code: int = 1008) -> int:
        """
        Close every socket of one account and return how many there were.

        A socket is authenticated once, at the handshake, and then lives on the
        session it was opened with — the cookie is never looked at again. Logging out
        in one tab deletes that cookie for the whole browser, but a second tab of the
        same session kept its socket and went on showing live data with no session
        behind it, until the tab was closed. So a logout closes the account's sockets
        here; the tab's reconnect handshake then has no cookie and is refused, and the
        page reloads itself onto the login page. The close code is 1008, the same the
        refusal uses, so the client counts it towards "three refusals and stop".

        Every socket of the *account*, not of the session: nothing here can tell two
        sessions of one user apart, and a tab that still holds a valid cookie simply
        reconnects. One manager per uvicorn worker, so this reaches the sockets of this
        worker only — the same in-process limit as the notification toasts.
        """
        client_ids = [cid for cid, uid in self.connection_users.items() if uid == user_id]
        for client_id in client_ids:
            await self.disconnect(client_id, code=code)
        return len(client_ids)

    async def connect(self, websocket: WebSocket, client_id: str, user_id: Optional[int] = None):
        """Accepts a new WebSocket connection and stores it, keyed to its account."""
        await websocket.accept()
        async with self._lock:
            self.active_connections[client_id] = websocket
            if user_id is not None:
                self.connection_users[client_id] = user_id
        logger.info(f"WebSocket client '{client_id}' connected.")

    async def disconnect(self, client_id: str, code: int = 1000):
        """
        Removes a WebSocket connection and all its subscriptions.

        The bookkeeping runs first and unconditionally; closing the socket is best effort
        and comes last. A client that simply vanished — closed tab, phone off the network —
        is the *normal* way a connection ends, and closing a socket whose peer is already
        gone raises: uvicorn signals ClientDisconnected and starlette re-raises it as
        WebSocketDisconnect(1006), which is not a RuntimeError. That escaped from here,
        with two consequences. The subscription cleanup below the close never ran, so the
        client id stayed in `subscriptions` forever: the topic never emptied and the
        broadcaster kept querying the database, parsing messages and packing a payload for
        that vehicle every 2 seconds, for nobody, until the next restart. And because the
        endpoint calls this from its `finally`, the exception propagated out of the ASGI
        app, so every ordinary disconnect printed a full traceback into the log.
        """
        async with self._lock:
            ws = self.active_connections.pop(client_id, None)
            self.connection_users.pop(client_id, None)

            for topic in list(self.subscriptions.keys()):
                subscribers = self.subscriptions[topic]
                subscribers.discard(client_id)
                if not subscribers:
                    del self.subscriptions[topic]

        if ws is None:
            # Already disconnected — broadcast_to_topic() reaps failed sends, and the
            # endpoint's `finally` reaps the same client a moment later.
            return

        try:
            # Nothing to send once either side has said goodbye; skipping it here is what
            # keeps the common case quiet. The guard is not sufficient on its own: a send
            # that fails is how we learn about the connections it cannot see.
            if (
                ws.application_state is not WebSocketState.DISCONNECTED
                and ws.client_state is not WebSocketState.DISCONNECTED
            ):
                await ws.close(code=code)
        except Exception as e:
            # Deliberately not a bare `except`: CancelledError is a BaseException and must
            # keep propagating during shutdown.
            logger.debug(f"Closing websocket connection for '{client_id}': {e}")

        logger.info(f"WebSocket client '{client_id}' disconnected and cleaned up.")

    def is_subscribed(self, client_id: str, topic: str) -> bool:
        """Whether this client already holds this topic. Unlocked: called on the loop."""
        return client_id in self.subscriptions.get(topic, ())

    def subscribers_of(self, topic: str) -> FrozenSet[str]:
        """
        A snapshot of who is subscribed to a topic, for the broadcaster's change
        detection. Unlocked on purpose: it is called on the event loop, where every
        mutation of the table also happens, so the read cannot interleave with one.
        """
        return frozenset(self.subscriptions.get(topic, ()))

    async def subscribe(self, client_id: str, topic: str):
        """Subscribes a client to a topic."""
        async with self._lock:
            if topic not in self.subscriptions:
                self.subscriptions[topic] = set()
            self.subscriptions[topic].add(client_id)
        logger.info(f"WebSocket client '{client_id}' subscribed to topic '{topic}'.")

    async def unsubscribe(self, client_id: str, topic: str):
        """Unsubscribes a client from a topic."""
        async with self._lock:
            if topic in self.subscriptions:
                self.subscriptions[topic].discard(client_id)
                if not self.subscriptions[topic]:
                    del self.subscriptions[topic]
        logger.info(f"WebSocket client '{client_id}' unsubscribed from topic '{topic}'.")

    async def broadcast_to_topic(self, topic: str, data: dict):
        """
        Broadcasts a message to all clients subscribed to a specific topic.
        This method now cleans up dead connections upon send failure.

        Every send is bounded by WS_SEND_TIMEOUT_SECONDS. A peer that has stopped
        reading — a laptop lid closed mid-frame, a phone that lost the network — leaves
        `send_bytes` waiting on a full TCP window until the protocol ping gives up on
        it, and the broadcaster awaits this gather: one such client held the live data
        of every other subscriber for that long. A send that times out counts as a
        failed one and the client is reaped like any other.
        """
        async with self._lock:
            if topic not in self.subscriptions:
                return

            client_ids_to_send = list(self.subscriptions.get(topic, set()))
            if not client_ids_to_send:
                return
            
            message_bytes = msgpack.packb(data, use_bin_type=True)
            
            tasks = []
            valid_client_ids_for_tasks = []
            for client_id in client_ids_to_send:
                if client_id in self.active_connections:
                    tasks.append(asyncio.wait_for(
                        self.active_connections[client_id].send_bytes(message_bytes),
                        timeout=settings.WS_SEND_TIMEOUT_SECONDS,
                    ))
                    valid_client_ids_for_tasks.append(client_id)
        
        if not tasks:
            return

        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        clients_to_disconnect = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                client_id_with_error = valid_client_ids_for_tasks[i]
                logger.warning(f"Send error for client '{client_id_with_error}' on topic '{topic}': {result}. Marking for disconnect.")
                clients_to_disconnect.append(client_id_with_error)
        
        if clients_to_disconnect:
            for client_id in clients_to_disconnect:
                await self.disconnect(client_id)

manager = WebSocketConnectionManager()