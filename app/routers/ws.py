import asyncio
import secrets
import logging
from datetime import datetime, timezone
from typing import Optional
from pathlib import Path
import aiofiles
import aiofiles.os

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, status

from app import crud
from app.database import SessionLocal
from app.websocket_manager import manager as ws_manager
from app.models import db as models_db
from app.config import settings
from app.security_manager import security_manager

logger = logging.getLogger(__name__)
router = APIRouter(tags=["WebSockets"])

def _client_ip(websocket: WebSocket) -> str:
    """
    The peer address, resolved the same way as for HTTP requests.

    uvicorn's ProxyHeadersMiddleware rewrites the client for WebSocket scopes too, so
    this is the real address behind a trusted proxy. See dependencies.get_client_ip()
    for why X-Forwarded-For must not be re-parsed here.
    """
    return websocket.client.host if websocket.client else "unknown"


def _authenticate_and_get_user(ticket: str, client_ip: str) -> Optional[models_db.User]:
    """
    Authenticates a ticket and returns the user, handling its own DB session.

    Two things this has to do itself, because nothing else covers it:

    * Check the IP block and count failures. Starlette's BaseHTTPMiddleware passes
      non-HTTP scopes straight through, so SecurityMiddleware — the global 429 for
      blocked addresses — never sees a WebSocket. A blocked IP could still open one and
      guess at tickets here without any attempt ever being recorded, while the same
      guess over HTTP was rate limited by dependencies.get_user_from_api_key().
    * Insist the key really is a WebSocket ticket. The handler *consumes* the key it
      authenticates with, and it used to delete whatever it was handed: passing a
      regular API key destroyed it, and passing the phone's device key took the MQTT
      password with it.
    """
    if security_manager.is_blocked(client_ip):
        logger.warning(f"WebSocket connection from blocked IP {client_ip} rejected.")
        return None

    db = SessionLocal()
    try:
        api_key = crud.apikey.get_api_key_by_raw_key(db, ticket)

        # An unknown ticket is a guess, exactly as an unknown API key is over HTTP.
        if not api_key:
            security_manager.record_failure(client_ip, 'apikey')
            return None

        if not crud.apikey.is_websocket_ticket_name(api_key.name):
            # A genuine credential used in the wrong place: reject, but do not count it
            # as guessing and above all do not consume it.
            logger.warning(
                f"WebSocket rejected a valid API key that is not a ticket "
                f"(prefix {api_key.key_prefix}) from {client_ip}. The key is untouched."
            )
            return None

        if not api_key.is_active or not api_key.user:
            return None

        expires_at = api_key.expires_at
        if expires_at is not None:
            # Only *naive* values are UTC by convention; forcing the timezone on an
            # already-aware one (PostgreSQL returns those) shifts the deadline by the
            # session offset. Same handling as dependencies.get_user_from_api_key().
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
            if expires_at < datetime.now(timezone.utc):
                return None

        current_user = api_key.user
        if not current_user.is_active:
            return None

        crud.apikey.delete_api_key_by_id_and_user(db, api_key_id=api_key.id, user_id=current_user.id)

        _ = current_user.is_admin
        _ = current_user.id

        return current_user
    finally:
        db.close()

@router.websocket("/ws", name="websocket_endpoint")
async def websocket_endpoint(
    websocket: WebSocket,
    ticket: str = Query(..., description="A short-lived API key obtained from /api/v1/ws-ticket")
):
    """
    Handles WebSocket connections for real-time vehicle data updates.
    """
    current_user = _authenticate_and_get_user(ticket, _client_ip(websocket))
    if not current_user:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    client_id = f"{current_user.username}_{secrets.token_hex(4)}"
    await ws_manager.connect(websocket, client_id)
    
    try:
        data = await websocket.receive_json()
        action = data.get("action")
        topic = data.get("topic")

        if action == "subscribe" and topic and topic.startswith("vehicle:"):
            is_authorized = False
            db = SessionLocal()
            try:
                vehicle_id = topic.split(":", 1)[1]
                db_vehicle = crud.vehicle.get_vehicle_by_vehicle_id(db, vehicle_id)
                if db_vehicle and (current_user.is_admin or db_vehicle.owner_id == current_user.id):
                    is_authorized = True
                
                if is_authorized:
                    await ws_manager.subscribe(client_id, topic)
                    while True:
                        await websocket.receive_text()
                else:
                    logger.warning(f"Client '{client_id}' unauthorized for vehicle topic '{topic}'.")
            finally:
                db.close()
        else:
            logger.warning(f"Client '{client_id}' sent unexpected message: {data}")

    except WebSocketDisconnect:
        logger.info(f"WebSocket client '{client_id}' disconnected.")
    except Exception as e:
        logger.error(f"An unexpected error occurred in WebSocket for '{client_id}': {e}", exc_info=True)
    finally:
        await ws_manager.disconnect(client_id)


@router.websocket("/ws/logs", name="websocket_logs_endpoint")
async def websocket_logs_endpoint(
    websocket: WebSocket,
    ticket: str = Query(..., description="A short-lived API key obtained from /api/v1/ws-ticket")
):
    """
    WebSocket endpoint for real-time server log streaming.
    Requires admin privileges.
    """
    current_user = _authenticate_and_get_user(ticket, _client_ip(websocket))
    if not current_user:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    # Only admins can view logs
    if not current_user.is_admin:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await websocket.accept()
    client_id = f"logs_{current_user.username}_{secrets.token_hex(4)}"
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
        try:
            await websocket.close()
        except Exception:
            # See above — must not swallow CancelledError.
            pass