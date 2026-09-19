from sqlalchemy.orm import Session, joinedload
from sqlalchemy import func
import datetime
import logging
from typing import Dict, Iterable, Optional, List

from app.models import db as models_db
from app.models import api as models_api
from app.services.mqtt_sync_worker import mqtt_sync_worker
from app.utils.crypto import encrypt_data
from app.websocket_manager import manager as websocket_manager, vehicle_topic

logger = logging.getLogger(__name__)

# How many ids one IN (...) carries. SQLite bound 999 host parameters per statement
# before 3.32, and every backend parses the list; the broadcaster asks for every
# vehicle anyone is watching in one call.
_IDS_PER_QUERY = 500

def get_vehicle_by_vehicle_id(db: Session, vehicle_id: str) -> Optional[models_db.Vehicle]:
    return db.query(models_db.Vehicle).options(joinedload(models_db.Vehicle.owner)).filter(models_db.Vehicle.vehicle_id == vehicle_id.upper()).first()

def get_vehicles_by_vehicle_ids(db: Session, vehicle_ids: Iterable[str]) -> Dict[str, models_db.Vehicle]:
    """
    The vehicles behind a set of ids, keyed by id; an id nobody has is simply absent.

    One round trip for the lot instead of one per id: the live-data broadcaster
    fetches every watched vehicle on every tick, and a fleet dashboard of ninety
    cards was ninety SELECTs every two seconds.
    """
    wanted = list({vehicle_id.upper() for vehicle_id in vehicle_ids})
    found: Dict[str, models_db.Vehicle] = {}
    for start in range(0, len(wanted), _IDS_PER_QUERY):
        rows = (
            db.query(models_db.Vehicle)
            .options(joinedload(models_db.Vehicle.owner))
            .filter(models_db.Vehicle.vehicle_id.in_(wanted[start:start + _IDS_PER_QUERY]))
            .all()
        )
        found.update({row.vehicle_id: row for row in rows})
    return found

def get_vehicle_by_id(db: Session, vehicle_db_id: int) -> Optional[models_db.Vehicle]:
    return db.query(models_db.Vehicle).options(joinedload(models_db.Vehicle.owner)).filter(models_db.Vehicle.id == vehicle_db_id).first()

def get_all_vehicles(db: Session, owner_id: Optional[int] = None, skip: int = 0, limit: int = 100) -> List[models_db.Vehicle]:
    query = db.query(models_db.Vehicle).options(joinedload(models_db.Vehicle.owner))
    if owner_id:
        query = query.filter(models_db.Vehicle.owner_id == owner_id)
    return query.order_by(models_db.Vehicle.vehicle_id).offset(skip).limit(limit).all()

def get_vehicle_count(db: Session) -> int:
    return db.query(func.count(models_db.Vehicle.id)).scalar()

def create_vehicle(db: Session, vehicle_in: models_api.VehicleCreate, owner_id: int) -> models_db.Vehicle:
    _encrypted_fields = {'server_password', 'module_password', 'ntfy_auth_token', 'ntfy_auth_password', 'paranoid_token'}
    vehicle_data = vehicle_in.model_dump(exclude_unset=True, exclude=_encrypted_fields)

    db_vehicle = models_db.Vehicle(**vehicle_data)
    db_vehicle.owner_id = owner_id
    db_vehicle.vehicle_id = vehicle_in.vehicle_id.upper()

    # Encrypt sensitive fields
    db_vehicle.encrypted_server_password = encrypt_data(vehicle_in.server_password)
    db_vehicle.encrypted_module_password = encrypt_data(vehicle_in.module_password) if vehicle_in.module_password else None
    if vehicle_in.ntfy_auth_token:
        db_vehicle.ntfy_auth_token = encrypt_data(vehicle_in.ntfy_auth_token)
    if vehicle_in.ntfy_auth_password:
        db_vehicle.ntfy_auth_password = encrypt_data(vehicle_in.ntfy_auth_password)
    if vehicle_in.paranoid_token:
        db_vehicle.paranoid_token = encrypt_data(vehicle_in.paranoid_token)
    
    db_vehicle.created_at = datetime.datetime.now(datetime.timezone.utc)
    db_vehicle.updated_at = datetime.datetime.now(datetime.timezone.utc)
    
    db.add(db_vehicle)
    db.commit()
    db.refresh(db_vehicle)
    
    if db_vehicle.protocol in ('v3', 'both'):
        mqtt_sync_worker.mark_vehicle_dirty(db_vehicle.vehicle_id)

    return db_vehicle

def update_vehicle(db: Session, vehicle_db_id: int, vehicle_in: models_api.VehicleUpdate) -> Optional[models_db.Vehicle]:
    db_vehicle = get_vehicle_by_id(db, vehicle_db_id)
    if not db_vehicle:
        return None
    
    old_protocol = db_vehicle.protocol
    old_vehicle_id = db_vehicle.vehicle_id
    update_data = vehicle_in.model_dump(exclude_unset=True)

    for field, value in update_data.items():
        if field == "server_password" and value is not None:
            db_vehicle.encrypted_server_password = encrypt_data(value)
        elif field == "module_password":
            db_vehicle.encrypted_module_password = encrypt_data(value) if value else None
        elif field == "vehicle_id" and value is not None:
            db_vehicle.vehicle_id = value.upper()
        elif field == "ntfy_auth_token":
            db_vehicle.ntfy_auth_token = encrypt_data(value) if value else None
        elif field == "ntfy_auth_password":
            db_vehicle.ntfy_auth_password = encrypt_data(value) if value else None
        elif field == "paranoid_token":
            db_vehicle.paranoid_token = encrypt_data(value) if value else None
        else:
            setattr(db_vehicle, field, value)

    db_vehicle.updated_at = datetime.datetime.now(datetime.timezone.utc)
    db.commit()
    db.refresh(db_vehicle)
    
    # The vehicle_id is immutable after creation (enforced by the UI and API routes),
    # so the broker entry keeps its username. Only this one entry is queued for the
    # sync worker; a full sync would re-derive the PBKDF2 hash for every vehicle.
    protocol_switched = old_protocol != db_vehicle.protocol
    password_changed = 'server_password' in update_data and update_data['server_password'] is not None

    if protocol_switched or password_changed:
        mqtt_sync_worker.mark_vehicle_dirty(db_vehicle.vehicle_id, acl=protocol_switched)

    if db_vehicle.vehicle_id != old_vehicle_id:
        websocket_manager.drop_topic_threadsafe(vehicle_topic(old_vehicle_id))

    return db_vehicle

def delete_vehicle(db: Session, vehicle_db_id: int) -> Optional[models_db.Vehicle]:
    db_vehicle = get_vehicle_by_id(db, vehicle_db_id)
    if db_vehicle:
        vehicle_id_to_remove = db_vehicle.vehicle_id
        protocol_was = db_vehicle.protocol
        
        db.delete(db_vehicle)
        db.commit()

        if protocol_was in ('v3', 'both'):
            # The row is gone, so the worker will simply drop the broker entry.
            mqtt_sync_worker.mark_vehicle_dirty(vehicle_id_to_remove)

        websocket_manager.drop_topic_threadsafe(vehicle_topic(vehicle_id_to_remove))

    return db_vehicle

def update_vehicle_message(db: Session, vehicle_id: str, msg_code_char: str, message_payload: str) -> Optional[models_db.Vehicle]:
    vehicle = get_vehicle_by_vehicle_id(db, vehicle_id.upper())
    if vehicle:
        full_message = f"{msg_code_char},{message_payload}"
        field_map = {'S': 'latest_status_msg', 'L': 'latest_location_msg', 'D': 'latest_diag_msg', 'F': 'latest_firmware_msg', 'W': 'latest_tpms_w_msg', 'Y': 'latest_tpms_y_msg', 'X': 'latest_export_power_msg'}
        if msg_code_char in field_map:
            setattr(vehicle, field_map[msg_code_char], full_message)
        vehicle.last_message_at = datetime.datetime.now(datetime.timezone.utc)
        db.commit()
        db.refresh(vehicle)
    return vehicle

def update_vehicle_last_seen_tcp(db: Session, vehicle_id: str, timestamp: Optional[datetime.datetime] = None) -> Optional[models_db.Vehicle]:
    vehicle = get_vehicle_by_vehicle_id(db, vehicle_id.upper())
    if vehicle:
        if timestamp is None:
            timestamp = datetime.datetime.now(datetime.timezone.utc)
        elif timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=datetime.timezone.utc)
        vehicle.last_seen_tcp = timestamp
        if vehicle.unused_reminder_sent_at is not None:
            vehicle.unused_reminder_sent_at = None
        db.commit()
        return vehicle
    return None

def update_vehicle_last_seen_v3(db: Session, vehicle_id: str, timestamp: datetime.datetime) -> Optional[models_db.Vehicle]:
    vehicle = get_vehicle_by_vehicle_id(db, vehicle_id.upper())
    if vehicle:
        aware_timestamp = timestamp.replace(tzinfo=datetime.timezone.utc) if timestamp.tzinfo is None else timestamp
        vehicle.last_seen_v3 = aware_timestamp
        vehicle.last_message_at = aware_timestamp
        if vehicle.unused_reminder_sent_at is not None:
            vehicle.unused_reminder_sent_at = None
        db.commit()
        return vehicle
    return None

def update_vehicle_paranoid_token(db: Session, vehicle_id: str, token: str) -> Optional[models_db.Vehicle]:
    vehicle = get_vehicle_by_vehicle_id(db, vehicle_id.upper())
    if vehicle:
        vehicle.paranoid_token = encrypt_data(token) if token else None
        vehicle.last_message_at = datetime.datetime.now(datetime.timezone.utc)
        db.commit()
        db.refresh(vehicle)
    return vehicle

def _make_tz_aware(dt) -> "Optional[datetime.datetime]":
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=datetime.timezone.utc)


def _vehicle_last_seen(vehicle: models_db.Vehicle) -> "Optional[datetime.datetime]":
    tcp = _make_tz_aware(vehicle.last_seen_tcp)
    v3 = _make_tz_aware(vehicle.last_seen_v3)
    candidates = [x for x in [tcp, v3] if x]
    if candidates:
        return max(candidates)
    return _make_tz_aware(vehicle.created_at)


def get_vehicles_needing_unused_warning(db: Session, inactive_days: int = 365) -> List[models_db.Vehicle]:
    """Non-admin-owned vehicles with no communication for inactive_days and no warning sent yet."""
    cutoff = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=inactive_days)
    candidates = (
        db.query(models_db.Vehicle)
        .join(models_db.User, models_db.Vehicle.owner_id == models_db.User.id)
        .filter(
            models_db.User.is_admin == False,
            models_db.Vehicle.unused_reminder_sent_at.is_(None),
        )
        .options(joinedload(models_db.Vehicle.owner))
        .all()
    )
    return [v for v in candidates if (ls := _vehicle_last_seen(v)) and ls <= cutoff]


def get_vehicles_to_auto_delete(db: Session, inactive_days: int = 365, grace_days: int = 7) -> List[models_db.Vehicle]:
    """Vehicles warned more than grace_days ago that are still inactive for inactive_days."""
    now = datetime.datetime.now(datetime.timezone.utc)
    inactive_cutoff = now - datetime.timedelta(days=inactive_days)
    grace_cutoff = now - datetime.timedelta(days=grace_days)
    candidates = (
        db.query(models_db.Vehicle)
        .join(models_db.User, models_db.Vehicle.owner_id == models_db.User.id)
        .filter(
            models_db.User.is_admin == False,
            models_db.Vehicle.unused_reminder_sent_at.isnot(None),
            models_db.Vehicle.unused_reminder_sent_at <= grace_cutoff,
        )
        .options(joinedload(models_db.Vehicle.owner))
        .all()
    )
    return [v for v in candidates if (ls := _vehicle_last_seen(v)) and ls <= inactive_cutoff]


def clear_unused_reminder(db: Session, vehicle_db_id: int) -> Optional[models_db.Vehicle]:
    """Clear unused_reminder_sent_at so the vehicle is no longer marked for auto-deletion."""
    vehicle = get_vehicle_by_id(db, vehicle_db_id)
    if vehicle:
        vehicle.unused_reminder_sent_at = None
        db.commit()
        db.refresh(vehicle)
    return vehicle


def update_vehicle_push_token(db: Session, vehicle_id: str, push_type: str, token_value: str) -> Optional[models_db.Vehicle]:
    vehicle = get_vehicle_by_vehicle_id(db, vehicle_id.upper())
    if not vehicle:
        logger.warning(f"Vehicle {vehicle_id} not found for push token update.")
        return None
    
    push_type_lower = push_type.lower()
    updated = False
    if push_type_lower in ("fcm", "gcm"): 
        if vehicle.fcm_token != token_value:
            vehicle.fcm_token = token_value
            updated = True
    elif push_type_lower == "apns":
        if vehicle.apns_token != token_value:
            vehicle.apns_token = token_value
            updated = True
    else:
        logger.warning(f"Unsupported push token type '{push_type}' for vehicle {vehicle_id}")
        return None
        
    if updated:
        vehicle.updated_at = datetime.datetime.now(datetime.timezone.utc)
        db.commit()
        db.refresh(vehicle)
        logger.info(f"Updated {push_type.upper()} token for vehicle {vehicle_id}")
    return vehicle