import asyncio
import datetime
from sqlalchemy.orm import Session

from app.connection_manager import manager, ClientConnection
from app.config import settings
from app import crud, notifications
from app.models.protocol import (
    StatusMessageData, LocationMessageData, EnvironmentMessageData, CommandResponseMessageData, AppCommandMessageData, PushSubscriptionData, HistoricalDataMessage,
    HistoricalDataMessageH, ProtocolDataBase
)
from typing import Callable, Awaitable, Any, Dict
import logging
from app.utils.crypto import decrypt_data
from app.utils.data_record_blocklist import get_record_blocklist
from .crypto import calculate_hmac_b64digest

logger = logging.getLogger(__name__)

_HISTORY_COMMAND_CODES = (30, 31, 32)
_HISTORY_COMMAND_MIN_INTERVAL_SECONDS = 5.0

_HISTORY_DUMP_WARN_THRESHOLD = 1_000

MessageHandler = Callable[[ClientConnection, Any, Session], Awaitable[None]]

async def _handle_car_ping(conn: ClientConnection, parsed_data: Any, db: Session):
    if conn.client_type == 'C' and conn.vehicle_id:
        logger.debug(f"TCP [{conn.vehicle_id}] Received Ping (A), sending Ack (a).")
        await conn.send_encrypted_message('a', '')

async def _handle_car_ping_ack(conn: ClientConnection, parsed_data: Any, db: Session):
    if conn.client_type == 'C' and conn.vehicle_id:
        logger.debug(f"TCP [{conn.vehicle_id}] Received Ping Ack (a).")
        conn.last_seen = asyncio.get_event_loop().time()

async def _handle_app_ping_or_ack(conn: ClientConnection, parsed_data: Any, db: Session):
    logger.debug(f"TCP [{conn.vehicle_id}] Received Ping/Ack from app.")

def _process_v2_charge_logging(
    db: Session,
    vehicle: Any,
    msg_code: str,
    msg_data: ProtocolDataBase
):
    """Process V2 protocol messages for charge logging integration.

    Processes if charge logging is enabled for this vehicle.
    Works alongside V3/MQTT — ChargeManager handles concurrent updates idempotently.
    Skip only if V3-only protocol (no V2 TCP expected for those vehicles).
    """
    if not vehicle.enable_charge_logging:
        return

    if vehicle.protocol == 'v3':
        return

    # Import here to avoid circular dependencies
    from app.services.charge_logger.charge_manager import charge_manager
    from app.metrics_manager import metrics_manager

    timestamp = datetime.datetime.now(datetime.timezone.utc)
    vehicle_id = vehicle.vehicle_id

    # Process 'D' message (EnvironmentMessageData) for charging state
    if msg_code == 'D' and isinstance(msg_data, EnvironmentMessageData):
        # D message has the charging boolean indicator
        charging_value = "yes" if msg_data.charging else "no"

        # Store in metrics_manager so charge_manager can access it
        metrics_manager.update_metric(vehicle_id, 'v.c.charging', charging_value)

        charge_manager.process_metric(
            vehicle_id,
            'v.c.charging',
            charging_value,
            timestamp
        )

        # Also process battery temperature if available
        if msg_data.temp_battery_c is not None:
            temp_str = str(msg_data.temp_battery_c)
            metrics_manager.update_metric(vehicle_id, 'v.b.temp', temp_str)
            charge_manager.process_metric(
                vehicle_id,
                'v.b.temp',
                temp_str,
                timestamp
            )

        # Capture odometer from D message (in tenths of unit, convert to km)
        if msg_data.odometer_10th_unit is not None:
            odometer_km = msg_data.odometer_10th_unit / 10.0
            odometer_str = str(odometer_km)
            metrics_manager.update_metric(vehicle_id, 'v.p.odometer', odometer_str)

    # Process 'L' message (LocationMessageData) for GPS position
    elif msg_code == 'L' and isinstance(msg_data, LocationMessageData):
        # Capture GPS coordinates
        if msg_data.latitude is not None:
            lat_str = str(msg_data.latitude)
            metrics_manager.update_metric(vehicle_id, 'v.p.latitude', lat_str)

        if msg_data.longitude is not None:
            lon_str = str(msg_data.longitude)
            metrics_manager.update_metric(vehicle_id, 'v.p.longitude', lon_str)

    # Process 'S' message (StatusMessageData) for SOC, power, and energy metrics
    elif msg_code == 'S' and isinstance(msg_data, StatusMessageData):
        # SOC (State of Charge percentage)
        if msg_data.soc is not None:
            soc_str = str(msg_data.soc)
            metrics_manager.update_metric(vehicle_id, 'v.b.soc', soc_str)
            charge_manager.process_metric(
                vehicle_id,
                'v.b.soc',
                soc_str,
                timestamp
            )

        # Charge power output in kW
        if msg_data.charge_power_output_kw is not None:
            power_str = str(msg_data.charge_power_output_kw)
            metrics_manager.update_metric(vehicle_id, 'v.c.power', power_str)
            charge_manager.process_metric(
                vehicle_id,
                'v.c.power',
                power_str,
                timestamp
            )

        # Energy consumed during charge (in tenths of kWh, so divide by 10)
        if msg_data.charge_energy_consumed_kwh10 is not None:
            # Convert from tenths to actual kWh
            energy_kwh = msg_data.charge_energy_consumed_kwh10 / 10.0
            energy_str = str(energy_kwh)
            metrics_manager.update_metric(vehicle_id, 'v.c.kwh', energy_str)
            charge_manager.process_metric(
                vehicle_id,
                'v.c.kwh',
                energy_str,
                timestamp
            )

async def _handle_car_data_message(conn: ClientConnection, msg_code: str, msg_data: ProtocolDataBase, db: Session):
    logger.debug(f"TCP Car {conn.vehicle_id} sent {msg_code}: {msg_data.raw_payload[:60]}...")

    updated_vehicle_obj = crud.vehicle.update_vehicle_message(db, conn.vehicle_id, msg_code, msg_data.raw_payload)

    if updated_vehicle_obj:
        # Process charge logging for V2 messages (if enabled and V3 is not active)
        if msg_code in ['S', 'D', 'L']:
            _process_v2_charge_logging(db, updated_vehicle_obj, msg_code, msg_data)

        await manager.forward_to_apps(conn.vehicle_id, msg_code, msg_data.raw_payload, conn)

async def _handle_car_tpms_message(conn: ClientConnection, code_char: str, parsed_data_or_raw_str: Any, db: Session):
    actual_raw_payload_str: str
    if isinstance(parsed_data_or_raw_str, ProtocolDataBase):
        actual_raw_payload_str = parsed_data_or_raw_str.raw_payload
    elif isinstance(parsed_data_or_raw_str, str):
        actual_raw_payload_str = parsed_data_or_raw_str
    else:
        logger.error(f"TPMS handler for '{code_char}' received unexpected data type: {type(parsed_data_or_raw_str)}")
        return

    logger.debug(f"TCP Car {conn.vehicle_id} sent TPMS '{code_char}'. Storing raw: {actual_raw_payload_str[:60]}")
    if crud.vehicle.update_vehicle_message(db, conn.vehicle_id, code_char, actual_raw_payload_str):
        await manager.forward_to_apps(conn.vehicle_id, code_char, actual_raw_payload_str, conn)

async def _handle_car_notification_message(conn: ClientConnection, raw_payload: str, db: Session):
    alert_type_char = 'I'
    content_after_type_char = raw_payload or "(Empty notification)"
    if raw_payload and raw_payload[0].upper() in ['I', 'A', 'W', 'E', 'F']:
        alert_type_char = raw_payload[0].upper()
        content_after_type_char = raw_payload[1:]

    parts = content_after_type_char.split(';', 1)
    id_part = parts[0] if len(parts) > 1 and ('.' in parts[0] or alert_type_char != 'I') else ""
    msg_text = parts[1] if len(parts) > 1 and id_part else content_after_type_char
    
    type_text = {'I': 'Info', 'A': 'Alert', 'W': 'Warning', 'E': 'Error', 'F': 'Firmware'}.get(alert_type_char, 'Notification')
    title = f"OVMS {type_text}: {conn.vehicle_id}{f' ({id_part})' if id_part else ''}"
    
    logger.info(f"TCP Car {conn.vehicle_id} sent P: Type='{alert_type_char}', ID='{id_part}', Title='{title}', Msg='{msg_text[:50]}'")
    asyncio.create_task(asyncio.to_thread(
        notifications.dispatch_notification_to_vehicle,
        vehicle_id=conn.vehicle_id, title=title, message_plain=msg_text,
        source_protocol='v2',
        ntfy_tags=["car_notification", alert_type_char.lower(), id_part.replace('.', '_') if id_part else "general"],
        fcm_data_payload={"notification_type": alert_type_char, "vehicle_id": conn.vehicle_id, "notification_id": id_part},
        alert_type_char=alert_type_char
    ))

async def _handle_car_command_response(conn: ClientConnection, msg_data: CommandResponseMessageData, db: Session):
    logger.debug(f"TCP Car {conn.vehicle_id} sent cmd response 'c' for cmd {msg_data.command_code}. Result: {msg_data.result_code}.")
    future = conn.command_futures.pop(f"c{msg_data.command_code}", None)
    if future and not future.done():
        future.set_result(msg_data.raw_payload)
    await manager.forward_to_apps(conn.vehicle_id, 'c', msg_data.raw_payload, conn)

async def _handle_car_paranoid_message(conn: ClientConnection, raw_payload: str, db: Session):
    if raw_payload.startswith('T'):
        crud.vehicle.update_vehicle_paranoid_token(db, conn.vehicle_id, raw_payload[1:])
    await manager.forward_to_apps(conn.vehicle_id, "E", raw_payload, conn)

async def _handle_car_historical_data(conn: ClientConnection, msg_data: HistoricalDataMessage, db: Session):
    """Handler for message 'h' (lowercase) - Historical data WITH acknowledgment.
    Format: ackcode,timediff,recordtype,recordnumber,lifetime,data (6 fields)
    """
    if not msg_data.ackcode:
        logger.error(f"TCP Car {conn.vehicle_id} sent malformed Historical message (h): {msg_data.raw_payload[:100]}")
        return

    if msg_data.record_type in get_record_blocklist(db):
        logger.debug(f"TCP Car {conn.vehicle_id}: data record type '{msg_data.record_type}' is blocklisted, dropped.")
        # Ack anyway so the module marks the record read instead of retransmitting it
        await conn.send_encrypted_message('h', msg_data.ackcode)
        return

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    crud.historical_data.save_historical_data(
        db, crud.vehicle.get_vehicle_by_vehicle_id(db, conn.vehicle_id),
        data_payload=msg_data.data_blob,
        record_type=msg_data.record_type,
        timestamp=now_utc + datetime.timedelta(seconds=msg_data.timediff_seconds),
        record_number=msg_data.record_number,
        expires_at=now_utc + datetime.timedelta(seconds=msg_data.lifetime_seconds) if msg_data.lifetime_seconds > 0 else None
    )
    # Send acknowledgment for lowercase 'h'
    await conn.send_encrypted_message('h', msg_data.ackcode)

async def _handle_car_historical_data_H(conn: ClientConnection, msg_data: HistoricalDataMessageH, db: Session):
    """Handler for message 'H' (uppercase) - Historical data WITHOUT acknowledgment.
    Format: recordtype,recordnumber,lifetime,data (4 fields)
    """
    if not msg_data.record_type or msg_data.record_type == "MALFORMED":
        logger.error(f"TCP Car {conn.vehicle_id} sent malformed Historical message (H): {msg_data.raw_payload[:100]}")
        return

    if msg_data.record_type in get_record_blocklist(db):
        logger.debug(f"TCP Car {conn.vehicle_id}: data record type '{msg_data.record_type}' is blocklisted, dropped.")
        return

    now_utc = datetime.datetime.now(datetime.timezone.utc)
    crud.historical_data.save_historical_data(
        db, crud.vehicle.get_vehicle_by_vehicle_id(db, conn.vehicle_id),
        data_payload=msg_data.data_blob,
        record_type=msg_data.record_type,
        timestamp=now_utc,  # Use current time, no timediff adjustment
        record_number=msg_data.record_number,
        expires_at=now_utc + datetime.timedelta(seconds=msg_data.lifetime_seconds) if msg_data.lifetime_seconds > 0 else None
    )
    # NO acknowledgment sent for uppercase 'H'

async def _handle_app_command_message(conn: ClientConnection, msg_data: AppCommandMessageData, db: Session):
    """Handle app command messages including historical data requests."""

    if msg_data.command_code in _HISTORY_COMMAND_CODES:
        now = asyncio.get_event_loop().time()
        if now - conn.last_history_command_at < _HISTORY_COMMAND_MIN_INTERVAL_SECONDS:
            logger.warning(
                f"TCP [{conn.vehicle_id}] throttled history command "
                f"{msg_data.command_code} from {conn.addr_str}."
            )
            await conn.send_encrypted_message(
                'c', f"{msg_data.command_code},1,Too many history requests, please wait"
            )
            return
        conn.last_history_command_at = now

    # Command 30: GPRS Utilisation Data (daily aggregated)
    if msg_data.command_code == 30:
        rows = crud.historical_data.get_historical_daily(db, conn.vehicle_id, record_type='*-OVM-Utilisation', days=90)
        if not rows:
            await conn.send_encrypted_message('c', "30,1,No GPRS utilisation data available")
            return

        for k, row in enumerate(rows, 1):
            response_payload = f"30,0,{k},{len(rows)},{row['u_date']},{row['data']}"
            await conn.send_encrypted_message('c', response_payload)
        return

    # Command 31: Historical Data Summary (aggregated statistics by record type)
    if msg_data.command_code == 31:
        # Parse optional since_date parameter (YYYY-MM-DD format)
        since_date = None
        if msg_data.arguments and msg_data.arguments[0]:
            try:
                since_date = datetime.datetime.strptime(msg_data.arguments[0], '%Y-%m-%d')
                since_date = since_date.replace(tzinfo=datetime.timezone.utc)
            except ValueError:
                logger.warning(f"Invalid date format for command 31: {msg_data.arguments[0]}")
                since_date = None

        rows = crud.historical_data.get_historical_summary(db, conn.vehicle_id, since_date=since_date)
        if not rows:
            await conn.send_encrypted_message('c', "31,1,No historical data available")
            return

        for k, row in enumerate(rows, 1):
            response_payload = (
                f"31,0,{k},{len(rows)},{row['h_recordtype']},"
                f"{row['distinctrecs']},{row['totalrecs']},{row['totalsize']},"
                f"{row['first']},{row['last']}"
            )
            await conn.send_encrypted_message('c', response_payload)
        return

    # Command 32: Historical Records (specific record type with optional since_date)
    if msg_data.command_code == 32:
        record_type = msg_data.arguments[0] if msg_data.arguments else None
        if not record_type:
            await conn.send_encrypted_message('c', "32,1,Record type not specified")
            return

        # Parse optional since_date parameter (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS format)
        since_date = None
        if len(msg_data.arguments) > 1 and msg_data.arguments[1]:
            try:
                # Try full datetime format first
                if ' ' in msg_data.arguments[1]:
                    since_date = datetime.datetime.strptime(msg_data.arguments[1], '%Y-%m-%d %H:%M:%S')
                else:
                    since_date = datetime.datetime.strptime(msg_data.arguments[1], '%Y-%m-%d')
                since_date = since_date.replace(tzinfo=datetime.timezone.utc)
            except ValueError:
                logger.warning(f"Invalid date format for command 32: {msg_data.arguments[1]}")
                since_date = None

        total = crud.historical_data.count_historical_data_for_vehicle(
            db, conn.vehicle_id,
            record_type_equals=record_type,
            since_date=since_date,
        )
        if not total:
            await conn.send_encrypted_message('c', "32,1,No historical data available")
            return

        if total >= _HISTORY_DUMP_WARN_THRESHOLD:
            logger.warning(
                f"TCP [{conn.vehicle_id}] command 32 is streaming {total} records of type "
                f"'{record_type}' to {conn.addr_str}."
            )

        records = crud.historical_data.iter_historical_data_for_vehicle(
            db, conn.vehicle_id,
            record_type_equals=record_type,
            since_date=since_date,
            sort_ascending=True,  # Oldest first (matching Perl behavior)
        )
        for k, record in enumerate(records, 1):
            ts = record.timestamp.strftime('%Y-%m-%d %H:%M:%S')
            response_payload = f"32,0,{k},{total},{record.record_type},{ts},{record.record_number or 0},{record.data_payload}"
            await conn.send_encrypted_message('c', response_payload)
        return

    # Forward other commands to car
    await manager.forward_to_car(conn.vehicle_id, msg_data.raw_payload, conn)

async def _handle_app_paranoid_message(conn: ClientConnection, raw_payload: str, db: Session):
    car_conn = manager.get_car_connection(conn.vehicle_id)
    vehicle_db = crud.vehicle.get_vehicle_by_vehicle_id(db, conn.vehicle_id)
    if car_conn and vehicle_db and vehicle_db.encrypted_module_password and raw_payload.startswith("T"):
        module_password_plain = decrypt_data(vehicle_db.encrypted_module_password)
        response_digest = calculate_hmac_b64digest(module_password_plain, raw_payload[1:])
        await car_conn.send_encrypted_message("E", f"S{response_digest}")
        logger.info(f"TCP Responded to Paranoid (E) request for {conn.vehicle_id} via app proxy.")

async def _handle_app_push_subscription(conn: ClientConnection, msg_data: PushSubscriptionData, db: Session):
    if not msg_data.vehicle_id or msg_data.vehicle_id.upper() != conn.vehicle_id.upper():
        logger.warning(f"Push subscription for {msg_data.vehicle_id} from app for {conn.vehicle_id}. Mismatch.")
        return

    vehicle_db = crud.vehicle.get_vehicle_by_vehicle_id(db, conn.vehicle_id)
    if vehicle_db and msg_data.net_pass == decrypt_data(vehicle_db.encrypted_server_password):
        push_type = (msg_data.push_type or "").lower()
        if push_type == "gcm" and settings.ALLOW_FCM_TOKEN_FROM_V2:
            crud.vehicle.update_vehicle_push_token(db, conn.vehicle_id, "fcm", msg_data.push_key_value)
        elif push_type == "apns" and settings.ALLOW_APNS_TOKEN_FROM_V2:
            crud.vehicle.update_vehicle_push_token(db, conn.vehicle_id, "apns", msg_data.push_key_value)

CAR_MESSAGE_HANDLERS: Dict[str, MessageHandler] = {
    'A': _handle_car_ping, 'a': _handle_car_ping_ack,
    'S': lambda c, p, s: _handle_car_data_message(c, 'S', p, s),
    'L': lambda c, p, s: _handle_car_data_message(c, 'L', p, s),
    'D': lambda c, p, s: _handle_car_data_message(c, 'D', p, s),
    'F': lambda c, p, s: _handle_car_data_message(c, 'F', p, s),
    'W': lambda c, p, s: _handle_car_tpms_message(c, 'W', p, s),
    'Y': lambda c, p, s: _handle_car_tpms_message(c, 'Y', p, s),
    'X': lambda c, p, s: _handle_car_data_message(c, 'X', p, s),
    'P': _handle_car_notification_message, 'c': _handle_car_command_response,
    'E': _handle_car_paranoid_message,
    'h': _handle_car_historical_data,      # lowercase h: WITH acknowledgment (6 fields)
    'H': _handle_car_historical_data_H,    # uppercase H: NO acknowledgment (4 fields)
}

APP_MESSAGE_HANDLERS: Dict[str, MessageHandler] = {
    'A': _handle_app_ping_or_ack, 'a': _handle_app_ping_or_ack,
    'C': _handle_app_command_message, 'E': _handle_app_paranoid_message,
    'p': _handle_app_push_subscription,
}