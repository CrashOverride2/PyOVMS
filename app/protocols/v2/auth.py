import base64
import hmac
from sqlalchemy.orm import Session

from app.connection_manager import manager, ClientConnection
from app.config import settings
from app import crud
from app.models import api as models_api
from app.database import SessionLocal
import logging
from app.utils.crypto import decrypt_data
from .crypto import (
    generate_server_token,
    calculate_hmac_digest,
    calculate_hmac_b64digest,
    create_rc4_cipher
)
from app.security_manager import security_manager
from app.security_events import security_event_logger, SecurityEventType

logger = logging.getLogger(__name__)


def _log_tcp_event(event_type: SecurityEventType, ip: str, details: dict = None) -> None:
    """Log a V2 TCP security event, opening its own DB session."""
    try:
        db = SessionLocal()
        try:
            security_event_logger.log_event(
                db=db, event_type=event_type,
                ip_address=ip, details=details or {}
            )
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Failed to log TCP security event {event_type}: {e}")

async def handle_authentication(conn: ClientConnection, line: str):
    client_ip = conn.addr[0] if conn.addr and len(conn.addr) > 0 else "unknown"
    
    if security_manager.is_blocked(client_ip):
        logger.critical(f"TCP Auth fail: Blocked IP {client_ip} attempted to connect. Closing.")
        _log_tcp_event(SecurityEventType.LOGIN_BLOCKED, client_ip, {"protocol": "v2tcp"})
        await conn.close()
        return

    # Never log the raw line: it carries the client token and the base64 HMAC digest,
    # which together are enough to brute-force the vehicle's server password offline
    # (that password is also the vehicle's MQTT password) and to replay the handshake.
    # LOG_FILE keeps five rotated copies and admins can stream it live over WebSocket.
    logger.debug(f"TCP Auth attempt from {conn.addr_str} ({len(line.strip())} bytes)")
    parts = line.strip().split()
    if len(parts) >= 5 and parts[0] in ("MP-A", "MP-B", "MP-C") and parts[1] == "0":
        client_protocol_type_char = parts[0][-1]
        client_token = parts[2]
        client_digest_b64 = parts[3]
        vehicle_id_from_client = parts[4].upper()

        conn.client_type = client_protocol_type_char
        conn.vehicle_id = vehicle_id_from_client
        logger.debug(f"TCP Auth: Client type '{conn.client_type}', Vehicle ID '{conn.vehicle_id}' from {conn.addr_str}")

        db: Session = SessionLocal()
        try:
            vehicle_db_info = crud.vehicle.get_vehicle_by_vehicle_id(db, vehicle_id_from_client)
            
            if not vehicle_db_info:
                logger.warning(f"TCP Auth fail: Unknown vehicle '{vehicle_id_from_client}' from {conn.addr_str}")
                security_manager.record_failure(client_ip, 'v2tcp')
                security_event_logger.log_event(
                    db=db, event_type=SecurityEventType.LOGIN_FAILED,
                    ip_address=client_ip,
                    details={"protocol": "v2tcp", "vehicle_id": vehicle_id_from_client, "reason": "unknown_vehicle"}
                )
                # Use the same silent close as a wrong-password failure to prevent vehicle-ID enumeration
                await conn.close()
                return

            # A deactivated owner cannot connect their vehicle. Without this the V2
            # path stayed open after an account was disabled: is_active was only ever
            # enforced in the HTTP dependencies, so the web UI closed while the car
            # kept authenticating, streaming and accepting commands. Same silent close
            # as an unknown vehicle, so this does not become a probe for which accounts
            # are disabled.
            if vehicle_db_info.owner and not vehicle_db_info.owner.is_active:
                logger.warning(
                    f"TCP Auth fail: vehicle '{vehicle_id_from_client}' belongs to the "
                    f"deactivated account '{vehicle_db_info.owner.username}' ({conn.addr_str})"
                )
                security_manager.record_failure(client_ip, 'v2tcp')
                security_event_logger.log_event(
                    db=db, event_type=SecurityEventType.LOGIN_FAILED,
                    ip_address=client_ip,
                    details={"protocol": "v2tcp", "vehicle_id": vehicle_id_from_client,
                             "reason": "owner_inactive"}
                )
                await conn.close()
                return

            try:
                server_password_to_use = decrypt_data(vehicle_db_info.encrypted_server_password)
            except Exception as e:
                logger.error(f"FATAL: Could not decrypt server password for vehicle {vehicle_id_from_client}. Check TOTP_ENCRYPTION_KEY. Error: {e}")
                await conn.close()
                return
            logger.debug(f"TCP Auth: Found vehicle '{conn.vehicle_id}' in DB. Using its server password.")

            expected_client_digest_bytes = calculate_hmac_digest(server_password_to_use, client_token)
            try:
                received_client_digest_bytes = base64.b64decode(client_digest_b64)
            except Exception:
                logger.warning(f"TCP Auth fail: Invalid base64 client_digest from {conn.vehicle_id} ({conn.addr_str})")
                security_manager.record_failure(client_ip, 'v2tcp')
                security_event_logger.log_event(
                    db=db, event_type=SecurityEventType.LOGIN_FAILED,
                    ip_address=client_ip,
                    details={"protocol": "v2tcp", "vehicle_id": vehicle_id_from_client, "reason": "invalid_digest_encoding"}
                )
                await conn.close()
                return
            if not hmac.compare_digest(expected_client_digest_bytes, received_client_digest_bytes):
                logger.warning(f"TCP Auth fail: Client digest mismatch for {conn.vehicle_id} from {conn.addr_str}")
                security_manager.record_failure(client_ip, 'v2tcp')
                security_event_logger.log_event(
                    db=db, event_type=SecurityEventType.LOGIN_FAILED,
                    ip_address=client_ip,
                    details={"protocol": "v2tcp", "vehicle_id": vehicle_id_from_client, "reason": "invalid_password"}
                )
                await conn.close()
                return

            # --- authenticated from here on ---------------------------------------
            #
            # The last_seen write used to sit before this comparison, so every peer
            # naming an existing vehicle id caused a Fernet decrypt and a DB commit.
            # Two consequences: the known-vehicle path was measurably slower than the
            # unknown one, which turned the deliberately identical error handling into
            # a vehicle-id enumeration oracle; and the write clears
            # unused_reminder_sent_at, so an unauthenticated peer could keep resetting
            # the 365-day inactivity warning and the auto-deletion that follows it.
            #
            # Cars only. An app authenticates with the same server password, and the
            # write used to run for it too: a phone that still had the vehicle
            # configured kept "last seen" current for a car that had not connected in
            # a year, so the warning never went out and the vehicle was never deleted.
            if conn.client_type == 'C':
                crud.vehicle.update_vehicle_last_seen_tcp(db, vehicle_id_from_client)

            conn.client_token = client_token
            conn.server_token = generate_server_token()
            server_digest_to_send_b64 = calculate_hmac_b64digest(server_password_to_use, conn.server_token)
            key_material_for_session = conn.server_token + conn.client_token
            session_key_bytes = calculate_hmac_digest(server_password_to_use, key_material_for_session)

            conn.tx_cipher = create_rc4_cipher(session_key_bytes)
            conn.rx_cipher = create_rc4_cipher(session_key_bytes)
            conn.authenticated = True
            logger.info(f"TCP Auth success for {conn.vehicle_id} ({conn.addr_str}) as type {conn.client_type}. Ciphers established.")
            security_event_logger.log_event(
                db=db, event_type=SecurityEventType.LOGIN_SUCCESS,
                ip_address=client_ip,
                details={"protocol": "v2tcp", "vehicle_id": vehicle_id_from_client, "client_type": conn.client_type}
            )

            await conn.send_raw_message(f"MP-S 0 {conn.server_token} {server_digest_to_send_b64}\r\n")
            
            manager.add_connection(conn) 

            if conn.client_type == 'C':
                logger.debug(f"TCP Sending server version to authenticated car {conn.vehicle_id}")
                await conn.send_encrypted_message("f", f"PyOVMS/{settings.SERVER_VERSION}")
            elif conn.client_type in ('A', 'B'):
                await _send_initial_data_to_app(conn, db)

        finally:
            db.close()
    else:
        # Same reason as above: even a malformed line may carry a real token/digest
        # (a truncated or slightly-off client still sends its credentials). Log the
        # shape, not the content.
        _fields = line.strip().split()
        logger.warning(
            f"TCP Invalid authentication attempt format from {conn.addr_str}: "
            f"{len(_fields)} field(s), first={_fields[0][:8] if _fields else '<empty>'!r}. Closing."
        )
        security_manager.record_failure(client_ip, 'v2tcp')
        _log_tcp_event(SecurityEventType.LOGIN_FAILED, client_ip, {"protocol": "v2tcp", "reason": "invalid_message_format"})
        await conn.close()


async def _send_initial_data_to_app(app_conn: ClientConnection, db: Session):
    """Sends initial status (Z, T) and stored messages to a newly authenticated app."""
    car_conn = manager.get_car_connection(app_conn.vehicle_id)
    car_is_online = bool(car_conn and car_conn.authenticated)
    staleness_T = 0 if car_is_online else manager._get_db_staleness(app_conn.vehicle_id, db)
    peer_count_Z = "1" if car_is_online else "0"
    
    logger.debug(f"TCP Sending initial Z({peer_count_Z}), T({staleness_T}), and stored messages to authenticated app {app_conn.vehicle_id} ({app_conn.addr_str})")
    await app_conn.send_encrypted_message("Z", peer_count_Z)
    await app_conn.send_encrypted_message("T", str(staleness_T))
    await _send_stored_messages_to_app(app_conn, db)


async def _send_stored_messages_to_app(app_conn: ClientConnection, db: Session):
    logger.debug(f"TCP Sending stored messages to app {app_conn.vehicle_id} ({app_conn.addr_str})")
    try:
        vehicle_db = crud.vehicle.get_vehicle_by_vehicle_id(db, app_conn.vehicle_id)
        if vehicle_db:
            message_map = {
                'F': vehicle_db.latest_firmware_msg, 'S': vehicle_db.latest_status_msg,
                'D': vehicle_db.latest_diag_msg, 'L': vehicle_db.latest_location_msg,
                'Y': vehicle_db.latest_tpms_y_msg, 'W': vehicle_db.latest_tpms_w_msg,
                'X': vehicle_db.latest_export_power_msg,
            }

            if message_map['F']:
                code, data = message_map['F'].split(',', 1)
                await app_conn.send_encrypted_message(code, data)
            
            await app_conn.send_encrypted_message("f", f"PyOVMS/{settings.SERVER_VERSION}")

            for code_char in ['S', 'D', 'L', 'X']: 
                if message_map.get(code_char):
                    code, data = message_map[code_char].split(',', 1)
                    await app_conn.send_encrypted_message(code, data)
            
            if message_map['Y']:
                code, data = message_map['Y'].split(',', 1)
                await app_conn.send_encrypted_message(code, data)
            elif message_map['W']:
                code, data = message_map['W'].split(',', 1)
                await app_conn.send_encrypted_message(code, data)
            
            if vehicle_db.paranoid_token:
                logger.debug(f"TCP Sending stored paranoid token to app {app_conn.vehicle_id}")
                plain_paranoid = decrypt_data(vehicle_db.paranoid_token)
                await app_conn.send_encrypted_message("E", f"T{plain_paranoid}")
            logger.debug(f"TCP Finished sending stored messages to app {app_conn.vehicle_id}")
        else:
            logger.warning(f"TCP No vehicle DB record found for {app_conn.vehicle_id} when trying to send stored messages.")
    except Exception as e:
        logger.error(f"Error sending stored messages to app {app_conn.vehicle_id}: {e}", exc_info=True)


async def handle_auto_provisioning(conn: ClientConnection, line: str):
    parts = line.strip().split()
    client_ip = conn.addr[0] if conn.addr and len(conn.addr) > 0 else "unknown"
    raw_key = parts[2] if len(parts) > 2 else 'N/A'
    key_hint = f"{raw_key[:4]}…(len={len(raw_key)})" if len(raw_key) > 4 else "N/A"
    logger.info(f"TCP Auto-Provisioning attempt from {conn.addr_str} with key: {key_hint}")
    if len(parts) == 3 and parts[0] == "AP-C" and parts[1] == "0":
        ap_key = parts[2]
        db: Session = SessionLocal()
        try:
            profile = crud.autoprovision.get_auto_provision_profile(db, ap_key)
            if profile and profile.owner and not profile.owner.is_active:
                logger.warning(
                    f"TCP AP Failed for key {key_hint} from {conn.addr_str}: owner "
                    f"account '{profile.owner.username}' is deactivated."
                )
                security_manager.record_failure(client_ip, 'v2tcp')
                await conn.send_raw_message("AP-X\r\n")
                await conn.close()
                return
            if profile and profile.owner:
                ap_server_token = generate_server_token()
                ap_server_digest_b64 = calculate_hmac_b64digest(ap_key, ap_server_token)
                encrypted_params = profile.encrypted_module_params_b64 or base64.b64encode(b"STUB_PARAMS").decode()
                response = f"AP-S 0 {ap_server_token} {ap_server_digest_b64} {encrypted_params}"
                await conn.send_raw_message(response + "\r\n")
                logger.info(f"TCP AP Success for key {key_hint} from {conn.addr_str}. Sent AP-S.")

                target_vid = profile.target_vehicle_id_str.upper()
                vehicle_db = crud.vehicle.get_vehicle_by_vehicle_id(db, target_vid)
                ap_server_pw = decrypt_data(profile.target_server_password)
                ap_module_pw = decrypt_data(profile.target_module_password) if profile.target_module_password else "OVMS"
                if not vehicle_db:
                    vehicle_in = models_api.VehicleCreate(
                        vehicle_id=target_vid,
                        vehicle_name=profile.target_vehicle_name or f"AP {ap_key[:8]}",
                        server_password=ap_server_pw,
                        module_password=ap_module_pw,
                        owner_id=profile.owner_id
                    )
                    crud.vehicle.create_vehicle(db, vehicle_in, owner_id=profile.owner_id)
                    logger.info(f"TCP Auto-provisioned and created vehicle: {target_vid} for user ID {profile.owner_id}")
                else:
                    # Ownership check: the AP profile must be owned by the same user as the vehicle
                    if vehicle_db.owner_id != profile.owner_id:
                        logger.warning(
                            f"TCP AP ownership mismatch for {target_vid}: "
                            f"profile owner {profile.owner_id} != vehicle owner {vehicle_db.owner_id}. "
                            f"Rejecting from {conn.addr_str}."
                        )
                        security_manager.record_failure(client_ip, 'v2tcp')
                        await conn.send_raw_message("AP-X\r\n")
                        return
                    server_password_plain = decrypt_data(vehicle_db.encrypted_server_password)
                    if server_password_plain != ap_server_pw:
                        vehicle_in_update = models_api.VehicleUpdate(server_password=ap_server_pw)
                        crud.vehicle.update_vehicle(db, vehicle_db.id, vehicle_in_update)
                        logger.info(f"TCP Auto-provisioned and updated password for existing vehicle: {target_vid}")
                    else:
                        logger.info(f"TCP Auto-provisioning for existing vehicle {target_vid}, password unchanged.")
            else:
                await conn.send_raw_message("AP-X\r\n")
                logger.warning(f"TCP AP Failed for key {key_hint} from {conn.addr_str}: Key not found, inactive, or no owner.")
                security_manager.record_failure(client_ip, 'v2tcp')
        finally:
            db.close()
        await conn.close()
    else:
        # The raw line is "AP-C 0 <ap_key>" — the provisioning secret. Log only its shape,
        # the same way the success path above uses key_hint.
        logger.warning(
            f"TCP Invalid AP-C format from {conn.addr_str}: "
            f"{len(line.strip().split())} field(s), {len(line.strip())} bytes. Closing."
        )
        security_manager.record_failure(client_ip, 'v2tcp')
        await conn.close()
