import asyncio
from sqlalchemy.orm import Session

from app import crud
from app.connection_manager import ClientConnection
from app.config import settings
from app.database import SessionLocal
from app.models.protocol import parse_protocol_message_payload, MESSAGE_PARSERS
from .auth import handle_authentication, handle_auto_provisioning
from .handlers import CAR_MESSAGE_HANDLERS, APP_MESSAGE_HANDLERS
from .crypto import DecryptionError, rc4_decrypt_b64
import logging
from app.security_manager import security_manager


logger = logging.getLogger(__name__)

# How often (seconds) a car's last_seen_tcp is persisted while it stays connected.
# Keeps the displayed V2 timestamp current without writing to the DB on every message.
_TCP_SEEN_PERSIST_INTERVAL = 60.0

async def handle_incoming_message(conn: ClientConnection, raw_message_line: str):
    conn.last_seen = asyncio.get_event_loop().time()
            
    if not conn.authenticated:
        if raw_message_line.startswith("AP-C"):
            await handle_auto_provisioning(conn, raw_message_line)
        elif raw_message_line.startswith("MP-"):
            await handle_authentication(conn, raw_message_line)
        else:
            logger.warning(f"TCP [{conn.addr_str}] Unknown initial message. Closing.")
            client_ip = conn.addr[0] if conn.addr and len(conn.addr) > 0 else "unknown"
            security_manager.record_failure(client_ip, 'v2tcp')
            await conn.close()
        return

    try:
        decrypted_message = rc4_decrypt_b64(conn.rx_cipher, raw_message_line.strip())
        if settings.DEBUG_TCP_PACKETS:
            logger.debug(f"TCP IN (CLEAR) [{conn.addr_str} <- {conn.vehicle_id}]: {repr(decrypted_message)}")
        
        if decrypted_message.startswith("MP-0 "):
            content = decrypted_message[5:]
            await _process_authenticated_mp0_message(conn, content[0], content[1:])
        else:
            logger.warning(f"TCP [{conn.vehicle_id}] Invalid MP-0 format: {repr(decrypted_message[:60])}.")
    except DecryptionError as e:
        logger.warning(f"TCP [{conn.vehicle_id}] Undecryptable message, closing connection: {e}")
        await conn.close()
    except Exception as e:
        logger.error(f"TCP [{conn.vehicle_id}] Error processing message: {e}", exc_info=True)
        await conn.close()

async def _process_authenticated_mp0_message(conn: ClientConnection, code: str, payload: str):
    db: Session = SessionLocal()
    try:
        handler_map = CAR_MESSAGE_HANDLERS if conn.client_type == 'C' else APP_MESSAGE_HANDLERS
        handler = handler_map.get(code)

        if handler:
            parsed_data = parse_protocol_message_payload(code, payload)
            expected_model = MESSAGE_PARSERS.get(code)
            
            if expected_model and not isinstance(parsed_data, expected_model):
                logger.critical(f"Parser for '{code}' failed. Handler expects {expected_model.__name__}, got {type(parsed_data).__name__}. Skipping call for safety.")
                return

            await handler(conn, parsed_data, db)
        else:
            logger.warning(f"TCP {conn.client_type} {conn.vehicle_id} sent unhandled MP-0 code '{code}'.")

        # Keep the V2 "last seen" timestamp current while the car is connected.
        # Throttled so we don't write on every message; the disconnect handler
        # writes a final timestamp so it freezes at the moment the car drops.
        if conn.client_type == 'C' and conn.vehicle_id:
            now = asyncio.get_event_loop().time()
            if now - conn.last_tcp_seen_persisted >= _TCP_SEEN_PERSIST_INTERVAL:
                crud.vehicle.update_vehicle_last_seen_tcp(db, conn.vehicle_id)
                conn.last_tcp_seen_persisted = now
    finally:
        db.close()