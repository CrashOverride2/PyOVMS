import asyncio
import secrets
import logging
import time
from typing import Optional
from pathlib import Path
from urllib.parse import urlsplit
import aiofiles
import aiofiles.os
import jwt as pyjwt
import msgpack

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect, status
from fastapi.concurrency import run_in_threadpool

from app import crud, security
from app.database import SessionLocal
from app.dependencies import _LEGACY_COOKIE, _SECURE_COOKIE
from app.websocket_manager import (
    USER_TOPIC_ALIAS, USER_TOPIC_PREFIX, VEHICLE_TOPIC_PREFIX, manager as ws_manager, user_topic,
    vehicle_topic,
)
from app.models import db as models_db
from app.config import settings
from app.security_manager import security_manager

logger = logging.getLogger(__name__)
router = APIRouter(tags=["WebSockets"])

# A rejected topic is echoed back so the page can drop that one card; the string is
# client-chosen, so it is cut before it reaches the log or the wire. The same cut
# applies to anything else of the client's that is logged.
_MAX_TOPIC_ECHO = 256

# How many subscribes one socket may have refused before it is closed. Every
# `vehicle:` subscribe is a database lookup on the threadpool, and an authenticated
# client could send them without bound; a dashboard earns one refusal per card whose
# vehicle disappeared while the tab was open, never a hundred. The answer to each
# stays the same (see the endpoint), so this is a cost cap, not an oracle.
_MAX_REJECTED_SUBSCRIBES = 20

# The longest topic that can name anything: `vehicle:` plus the vehicle_id column.
# Anything longer is answered like an unauthorized one, *before* it is looked up or
# logged — the string is client-chosen, so without this it was a database parameter
# of up to the frame limit for a `vehicle:` subscribe and, on an `unsubscribe`, an
# uncut INFO line in the log.
_MAX_TOPIC_LENGTH = len(VEHICLE_TOPIC_PREFIX) + models_db.Vehicle.vehicle_id.type.length


class LookupThrottle:
    """
    A token bucket for the database lookups one socket may cause.

    Every `vehicle:` subscribe for a topic the socket does not hold yet is a query on
    the threadpool, and `_MAX_REJECTED_SUBSCRIBES` only bounds the *refused* ones: a
    client subscribing and unsubscribing its own vehicle in a loop had a query per
    message, and nothing else limited how fast it could send them. The budget is
    per socket (a new socket costs a handshake, which is a query of its own) and a
    subscribe past it *waits* rather than being refused — `acquire()` returns the
    seconds to sleep before the lookup may run, and the endpoint reads no further
    message until then, which is the back-pressure. A dashboard sends one subscribe
    per card when it connects, so the burst is sized for a fleet page and a normal
    tab never waits at all.

    Not thread-safe on purpose: one instance per socket, used from its coroutine.
    """

    def __init__(self, burst: int, per_second: float, clock=time.monotonic):
        self._burst = float(max(1, burst))
        self._rate = float(per_second)
        self._clock = clock
        self._tokens = self._burst
        self._at = clock()

    def acquire(self) -> float:
        now = self._clock()
        if self._rate > 0:
            self._tokens = min(self._burst, self._tokens + (now - self._at) * self._rate)
        self._at = now
        self._tokens -= 1.0
        if self._tokens >= 0.0 or self._rate <= 0:
            # A rate of zero means "no limit" and would divide by zero below.
            return 0.0
        return -self._tokens / self._rate


def _client_ip(websocket: WebSocket) -> str:
    """
    The peer address, resolved the same way as for HTTP requests.

    uvicorn's ProxyHeadersMiddleware rewrites the client for WebSocket scopes too, so
    this is the real address behind a trusted proxy. See dependencies.get_client_ip()
    for why X-Forwarded-For must not be re-parsed here.
    """
    return websocket.client.host if websocket.client else "unknown"


def _netloc(url: str) -> str:
    return urlsplit(url).netloc.lower()


def origin_is_ours(origin: Optional[str], host: Optional[str], secure: bool = False) -> bool:
    """
    Whether a WebSocket handshake comes from a page this server served.

    The socket is authenticated by the session cookie, and a browser attaches that
    cookie to a handshake started by *any* site — cross-site WebSocket hijacking is a
    page on evil.example opening `wss://ovms.example/ws` and reading the owner's live
    data. `SameSite=Lax` on the cookie already stops that in every current browser;
    this check is the second lock, so the guarantee does not rest on one cookie
    attribute. The Origin header is set by the browser and cannot be forged from
    script. It must match the Host the handshake was sent to, or the origin this
    deployment is configured under (a reverse proxy that rewrites Host to the upstream
    name would otherwise refuse its own pages). No Origin at all is not a browser, and
    a non-browser client has no cookie to protect — refused.

    `secure` is whether the handshake itself arrived over TLS. Then the page must be
    an https one too: cookies are attached by the target URL, not the page's origin,
    so a plain-http page on the same name — a network position, not a bug in our
    pages — would otherwise pass the name check and get the cookie's socket. Keyed on
    the handshake, not on FORCE_SECURE_COOKIES: that is on by default, and a local
    http://localhost deployment (where browsers do send Secure cookies) must keep
    working.
    """
    if not origin or not host:
        return False
    parts = urlsplit(origin)
    wanted = parts.netloc.lower()
    if not wanted:
        return False
    if secure and parts.scheme.lower() != "https":
        return False
    allowed = {host.lower(), _netloc(settings.SERVER_BASE_URL), _netloc(settings.WEBAUTHN_ORIGIN)}
    allowed.discard("")
    return wanted in allowed


def _is_secure(websocket: WebSocket) -> bool:
    """Whether this handshake counts as TLS — the same rule the cookie dependency uses."""
    return settings.FORCE_SECURE_COOKIES or websocket.url.scheme in ("https", "wss")


def _session_token(websocket: WebSocket) -> Optional[str]:
    """The session cookie, with the same __Host- rule as dependencies._get_access_token()."""
    token = websocket.cookies.get(_SECURE_COOKIE)
    if token:
        return token
    if _is_secure(websocket):
        return None
    return websocket.cookies.get(_LEGACY_COOKIE)


def _token_expiry(token: str) -> Optional[float]:
    """
    The `exp` claim of a token that decode_jwt_and_get_user() has already verified,
    as a POSIX timestamp — or None if it carries none.

    Read without verification on purpose: the signature, audience and issuer were
    checked a moment ago on the same string, and this only wants the deadline.
    """
    try:
        value = token.split(' ', 1)[1] if token.startswith("Bearer ") else token
        payload = pyjwt.decode(value, options={"verify_signature": False})
    except Exception:
        return None
    exp = payload.get("exp")
    return float(exp) if isinstance(exp, (int, float)) and not isinstance(exp, bool) else None


def _seconds_until(deadline: Optional[float]) -> Optional[float]:
    """How long a socket may still wait for a message before its session is over."""
    if deadline is None:
        return None
    return max(0.0, deadline - time.time())


async def _authenticate_websocket(websocket: WebSocket) -> Optional[models_db.User]:
    """
    The fully authenticated user behind a WebSocket handshake, or None.

    The same session cookie every page is rendered with, checked the same way
    (`decode_jwt_and_get_user` with the MFA claim enforced — a session parked on the
    TOTP page gets no socket). It used to be a one-shot API-key ticket the page fetched
    first: two writes and a commit per socket, a secret in the query string of every
    proxy log, and a housekeeping pass for the tickets whose socket never came. All
    three consumers were browser pages that already hold the cookie.

    Two things this has to do itself, because nothing else covers a WebSocket:

    * Check the IP block. Starlette's BaseHTTPMiddleware passes non-HTTP scopes straight
      through, so SecurityMiddleware — the global 429 for blocked addresses — never sees
      a handshake.
    * Check the Origin (see origin_is_ours). A bad cookie is not counted as a failed
      attempt: the token is signed, there is nothing to guess, and an expired session
      reconnecting from a tab left open is the ordinary case.

    The socket is authenticated here and never again, so the session's end has to be
    carried along: `websocket.state.session_deadline` is the token's `exp`, and the
    endpoints close the socket when it passes. A logout is the other way a session
    ends before the token does; that closes the account's sockets through
    `ws_manager.disconnect_user()`. Without either, a tab outlived its session
    indefinitely and went on showing live data.
    """
    client_ip = _client_ip(websocket)
    if security_manager.is_blocked(client_ip):
        logger.warning(f"WebSocket connection from blocked IP {client_ip} rejected.")
        return None

    if not origin_is_ours(
        websocket.headers.get("origin"), websocket.headers.get("host"),
        secure=websocket.url.scheme in ("https", "wss"),
    ):
        logger.warning(
            f"WebSocket handshake from {client_ip} refused: origin "
            f"{websocket.headers.get('origin')!r} is not this server."
        )
        return None

    token = _session_token(websocket)
    if not token:
        return None

    # One SELECT on `users`, on the loop — the same call every page's cookie dependency
    # makes inline. Attributes the handler reads after the session is gone are loaded
    # here.
    db = SessionLocal()
    try:
        try:
            current_user = await security.decode_jwt_and_get_user(token=token, db=db, ignore_mfa_check=False)
        except HTTPException:
            return None
        if not current_user or not current_user.is_active:
            return None
        _ = current_user.is_admin
        _ = current_user.id
        _ = current_user.username
        websocket.state.session_deadline = _token_expiry(token)
        return current_user
    finally:
        db.close()


async def _refuse(websocket: WebSocket) -> None:
    """
    Refuse a handshake with a 1008 close frame the browser can see.

    `close()` before `accept()` makes uvicorn answer the upgrade with HTTP 403
    instead — no WebSocket ever exists, so the page's `CloseEvent.code` is 1006,
    the same code a dropped connection produces. The "three refusals and stop"
    guard in base.html and index.html never counted one, and a tab left open
    across a logout reconnected every 30 s forever. (Starlette's TestClient
    reports 1008 either way, which is why the tests did not notice.)
    """
    await websocket.accept()
    await websocket.close(code=status.WS_1008_POLICY_VIOLATION)


def resolve_user_topic(requested: str, user_id: int) -> Optional[str]:
    """
    The routing key of the caller's own `user:` topic, or None.

    The client says `user:me` and nothing else; the id behind it is always taken from
    the authenticated session. There is no administrative reading of another person's
    notifications, so nothing here consults is_admin.

    Only the alias is accepted, on purpose. A frame on this topic is tagged `user:me`
    (see notifications/web.py), because the page matches it on the string it
    subscribed with. It used to accept the caller's own numeric id "harmlessly" as
    well — a subscription that would receive frames it can never match is not
    harmless, so it is refused like any other id.
    """
    if requested == USER_TOPIC_ALIAS:
        return user_topic(user_id)
    return None


def _canonical_topic(requested: str, user_id: int) -> str:
    """
    The name the manager would hold this topic under, without any lookup: the
    caller's own routing key for the alias, the stored spelling of a vehicle id.
    What `is_subscribed` and `unsubscribe` are keyed on, so a page that sent
    `vehicle:car1` finds the entry `_resolve_vehicle_topic` made as `vehicle:CAR1`.
    """
    own = resolve_user_topic(requested, user_id)
    if own is not None:
        return own
    if requested.startswith(VEHICLE_TOPIC_PREFIX):
        return vehicle_topic(requested[len(VEHICLE_TOPIC_PREFIX):].upper())
    return requested


def _resolve_vehicle_topic(requested: str, current_user: models_db.User) -> Optional[str]:
    """
    The vehicle topic if this user may watch it (owner or admin), else None.

    Returned in its canonical spelling — the stored id, which the pages send — so one
    vehicle is one topic in the manager, whatever case the subscribe came in: the
    broadcaster builds one payload per topic, and a withdrawal (`drop_topic`, when
    the vehicle is deleted) has to find every subscriber under one name.
    """
    vehicle_id = requested[len(VEHICLE_TOPIC_PREFIX):]
    if not vehicle_id:
        return None
    db = SessionLocal()
    try:
        db_vehicle = crud.vehicle.get_vehicle_by_vehicle_id(db, vehicle_id)
        if db_vehicle and (current_user.is_admin or db_vehicle.owner_id == current_user.id):
            return vehicle_topic(db_vehicle.vehicle_id)
        return None
    finally:
        # Closed before the receive loop: the session is only needed for this lookup,
        # and holding it for the life of the socket cost a pool connection per open
        # vehicle page.
        db.close()


@router.websocket("/ws", name="websocket_endpoint")
async def websocket_endpoint(websocket: WebSocket):
    """
    Handles WebSocket connections for real-time vehicle data updates and per-user
    notifications. Authenticated by the session cookie; any number of subscriptions
    per connection, `vehicle:<id>` and `user:me`, each authorized on its own.
    """
    current_user = await _authenticate_websocket(websocket)
    if not current_user:
        await _refuse(websocket)
        return

    client_id = f"{current_user.username}_{secrets.token_hex(4)}"
    await ws_manager.connect(websocket, client_id, user_id=current_user.id)
    deadline = getattr(websocket.state, "session_deadline", None)
    rejected = 0
    lookups = LookupThrottle(settings.WS_SUBSCRIBE_LOOKUP_BURST, settings.WS_SUBSCRIBE_LOOKUPS_PER_SECOND)

    try:
        # Any number of subscriptions per connection, each authorized on its own. The
        # dashboard subscribes to every vehicle of the account over one socket; the
        # vehicle page to one. A subscribe that is not authorized is answered with
        # `subscribe_rejected` and nothing else happens — the same answer for a
        # vehicle that is not theirs, a user id that is not theirs and a vehicle that
        # does not exist, so the socket is no oracle for vehicle ids. It used to close
        # the socket: a dashboard with one card whose vehicle had been deleted while
        # the tab was open then re-sent that subscribe on every reconnect, and no
        # card on the page got live data again until reload. A message that is not a
        # subscribe or unsubscribe at all still closes the socket, and every
        # subscription is dropped with it (`finally`).
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_json(), timeout=_seconds_until(deadline))
            except asyncio.TimeoutError:
                # The session token expired while the socket was open. Every page
                # request would be redirected to the login page now; the socket
                # follows, with the refusal code so the tab knows not to insist.
                logger.info(f"Client '{client_id}': session expired; closing.")
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                break
            except (ValueError, KeyError):
                # Not JSON, or a binary frame (`receive_json` reads the text key). A
                # client can send this at will, so it is one WARNING line and a 1003
                # close — not an ERROR with a traceback per message, which is what the
                # generic handler below would make of it.
                logger.warning(f"Client '{client_id}' sent a message that is not JSON; closing.")
                await websocket.close(code=status.WS_1003_UNSUPPORTED_DATA)
                break
            action = data.get("action") if isinstance(data, dict) else None
            topic = data.get("topic") if isinstance(data, dict) else None

            resolved: Optional[str] = None
            if action == "subscribe" and isinstance(topic, str) and topic:
                if len(topic) > _MAX_TOPIC_LENGTH:
                    resolved = None
                elif topic.startswith(USER_TOPIC_PREFIX):
                    # `user:me` names the caller's own routing key; resolving it costs
                    # nothing, and the set add below is idempotent for a re-send.
                    resolved = resolve_user_topic(topic, current_user.id)
                elif ws_manager.is_subscribed(client_id, _canonical_topic(topic, current_user.id)):
                    # Already authorized on this socket (a page re-sending its set);
                    # nothing to look up.
                    continue
                elif topic.startswith(VEHICLE_TOPIC_PREFIX):
                    # Past this socket's budget the lookup waits its turn; see
                    # LookupThrottle. Then synchronous SQLAlchemy work on the
                    # threadpool: inline, a slow query would stall every socket and
                    # response of this worker for its duration.
                    delay = lookups.acquire()
                    if delay > 0:
                        await asyncio.sleep(delay)
                    resolved = await run_in_threadpool(_resolve_vehicle_topic, topic, current_user)
                if resolved is None:
                    rejected += 1
                    logger.warning(f"Client '{client_id}' unauthorized for topic '{topic[:_MAX_TOPIC_ECHO]}'.")
                    await websocket.send_bytes(msgpack.packb(
                        {"type": "subscribe_rejected", "topic": topic[:_MAX_TOPIC_ECHO]}, use_bin_type=True))
                    if rejected >= _MAX_REJECTED_SUBSCRIBES:
                        logger.warning(f"Client '{client_id}': {rejected} refused subscribes; closing.")
                        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                        break
                    continue
                await ws_manager.subscribe(client_id, resolved)
            elif action == "unsubscribe" and isinstance(topic, str) and 0 < len(topic) <= _MAX_TOPIC_LENGTH:
                # Only ever removes this client's own entry; nothing to authorize. The
                # alias names the caller's own key here as on subscribe. The manager
                # logs the topic, hence the length bound.
                await ws_manager.unsubscribe(client_id, _canonical_topic(topic, current_user.id))
            else:
                # Client-chosen content: cut before it reaches the log. Uncut, one
                # message near uvicorn's frame limit was a 16 MB log line.
                logger.warning(f"Client '{client_id}' sent unexpected message: {str(data)[:_MAX_TOPIC_ECHO]}")
                break

    except WebSocketDisconnect:
        logger.info(f"WebSocket client '{client_id}' disconnected.")
    except Exception as e:
        logger.error(f"An unexpected error occurred in WebSocket for '{client_id}': {e}", exc_info=True)
    finally:
        await ws_manager.disconnect(client_id)


@router.websocket("/ws/logs", name="websocket_logs_endpoint")
async def websocket_logs_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for real-time server log streaming.
    Authenticated by the session cookie; requires admin privileges.
    """
    current_user = await _authenticate_websocket(websocket)
    if not current_user:
        await _refuse(websocket)
        return

    # Only admins can view logs
    if not current_user.is_admin:
        await _refuse(websocket)
        return

    # Registered with the manager, subscribed to nothing: that is what lets a logout
    # find and close it (`disconnect_user`), the same as the live-data socket.
    client_id = f"logs_{current_user.username}_{secrets.token_hex(4)}"
    await ws_manager.connect(websocket, client_id, user_id=current_user.id)
    deadline = getattr(websocket.state, "session_deadline", None)
    logger.info(f"Log viewer WebSocket client '{client_id}' connected")

    log_file_path = settings.LOG_FILE
    if not log_file_path or not Path(log_file_path).exists():
        await websocket.send_json({"type": "error", "message": "Log file not found"})
        await websocket.close()
        return

    last_size = 0

    try:
        # Send initial log lines (last 200 lines)
        async with aiofiles.open(log_file_path, 'r', encoding='utf-8') as f:
            lines = await f.readlines()
            last_size = await f.tell()
            initial_lines = [line.strip() for line in lines[-200:] if line.strip()]
            if initial_lines:
                await websocket.send_json({"type": "initial", "lines": initial_lines})

        # Stream new log lines
        while True:
            try:
                if _seconds_until(deadline) == 0.0:
                    logger.info(f"Log viewer '{client_id}': session expired; closing.")
                    await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                    break
                # Check for client messages or disconnection (with short timeout)
                try:
                    msg = await asyncio.wait_for(websocket.receive_text(), timeout=1.0)
                    # Handle pause/resume if needed
                    if msg == "ping":
                        await websocket.send_text("pong")
                except asyncio.TimeoutError:
                    # Normal - no message from client, continue checking logs
                    pass

                # Check for new log content
                current_size = await aiofiles.os.path.getsize(log_file_path)

                # Log was rotated/truncated
                if current_size < last_size:
                    async with aiofiles.open(log_file_path, 'r', encoding='utf-8') as f:
                        new_lines = await f.readlines()
                        last_size = await f.tell()
                        filtered_lines = [line.strip() for line in new_lines if line.strip()]
                        if filtered_lines:
                            await websocket.send_json({"type": "reset", "lines": filtered_lines[-200:]})

                # New content available
                elif current_size > last_size:
                    async with aiofiles.open(log_file_path, 'r', encoding='utf-8') as f:
                        await f.seek(last_size)
                        new_lines = await f.readlines()
                        last_size = await f.tell()

                        # Filter out WebSocket log requests to reduce noise
                        filtered_lines = [
                            line.strip() for line in new_lines
                            if line.strip() and '/ws/logs' not in line
                        ]

                        if filtered_lines:
                            await websocket.send_json({"type": "update", "lines": filtered_lines})

            except asyncio.CancelledError:
                # Server shutting down - clean disconnect
                logger.info(f"Log viewer '{client_id}' cancelled (shutdown)")
                raise

    except WebSocketDisconnect:
        logger.info(f"Log viewer WebSocket client '{client_id}' disconnected")
    except asyncio.CancelledError:
        logger.info(f"Log viewer WebSocket client '{client_id}' cancelled during shutdown")
        raise
    except Exception as e:
        logger.error(f"Error in log viewer WebSocket for '{client_id}': {e}", exc_info=True)
        try:
            await websocket.send_json({"type": "error", "message": "An internal server error occurred in the log stream."})
        except Exception:
            # Not a bare `except`: CancelledError derives from BaseException, so a bare
            # one swallows the cancellation this task is being shut down with and the
            # server waits on it during shutdown. The socket being gone is the expected
            # case here — that is why we are in the error path at all.
            pass
    finally:
        logger.debug(f"Log viewer WebSocket '{client_id}' ended")
        # Closes the socket (best effort, never raises) and drops the registration.
        await ws_manager.disconnect(client_id)