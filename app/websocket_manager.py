import asyncio
import logging
from typing import Dict, Set
from fastapi import WebSocket
from starlette.websockets import WebSocketState
import msgpack

logger = logging.getLogger(__name__)

class WebSocketConnectionManager:
    """Manages active WebSocket connections and topic-based subscriptions."""

    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.subscriptions: Dict[str, Set[str]] = {}
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, client_id: str):
        """Accepts a new WebSocket connection and stores it."""
        await websocket.accept()
        async with self._lock:
            self.active_connections[client_id] = websocket
        logger.info(f"WebSocket client '{client_id}' connected.")

    async def disconnect(self, client_id: str):
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
                await ws.close()
        except Exception as e:
            # Deliberately not a bare `except`: CancelledError is a BaseException and must
            # keep propagating during shutdown.
            logger.debug(f"Closing websocket connection for '{client_id}': {e}")

        logger.info(f"WebSocket client '{client_id}' disconnected and cleaned up.")

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
                    tasks.append(self.active_connections[client_id].send_bytes(message_bytes))
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