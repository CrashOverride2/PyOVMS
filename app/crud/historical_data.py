from sqlalchemy.orm import Session
from sqlalchemy import desc, or_, and_, not_, func
import datetime
from typing import Optional, List, Dict, Any

from app.models import db as models_db
import logging

logger = logging.getLogger(__name__)

_MAX_DATA_PAYLOAD_BYTES = 65_536   # 64 KiB per record
_MAX_ROWS_PER_VEHICLE = 10_000     # hard cap; oldest rows pruned when exceeded
_CRASH_LOG_RETENTION_DAYS = 90    # crash logs expire after this, not forever

def save_historical_data(db: Session, vehicle_db_obj: models_db.Vehicle, data_payload: str,
                         record_type: str,
                         timestamp: Optional[datetime.datetime] = None,
                         record_number: Optional[int] = None,
                         expires_at: Optional[datetime.datetime] = None,
                         allow_update: bool = True):
    if not vehicle_db_obj:
        return None

    # Enforce maximum payload size
    if data_payload and len(data_payload.encode('utf-8', errors='replace')) > _MAX_DATA_PAYLOAD_BYTES:
        logger.warning(
            f"Historical data payload too large for {vehicle_db_obj.vehicle_id} "
            f"({len(data_payload)} chars, type {record_type}). Truncating."
        )
        data_payload = data_payload[:_MAX_DATA_PAYLOAD_BYTES]

    timestamp = timestamp or datetime.datetime.now(datetime.timezone.utc)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=datetime.timezone.utc)

    if expires_at and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=datetime.timezone.utc)

    is_crash_log = 'crash' in record_type.lower()

    # Crash logs must have a bounded expiry — never allowed to persist forever
    max_crash_expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=_CRASH_LOG_RETENTION_DAYS)
    if is_crash_log:
        if expires_at is None or expires_at > max_crash_expiry:
            expires_at = max_crash_expiry

    existing_entry = None

    # Only check for existing records for special historical messages (record_number > 0)
    # Regular messages (S,L,D,F,X) use record_number=0 and should always create new entries.
    # Callers pass allow_update=False for records whose number is NOT a unique key (e.g. the
    # framework session logs *-LOG-Trip / *-LOG-Grid carry a constant format version there) -
    # those must append to build a history instead of overwriting the previous record.
    if allow_update and record_number is not None and record_number > 0 and not is_crash_log:
        existing_entry = db.query(models_db.HistoricalData).filter_by(
            vehicle_id_fk=vehicle_db_obj.id,
            record_type=record_type,
            record_number=record_number
        ).first()

    if existing_entry:
        logger.debug(f"Updating existing historical record for {vehicle_db_obj.vehicle_id}, type {record_type}, num {record_number}")
        existing_entry.data_payload = data_payload
        existing_entry.timestamp = timestamp
        existing_entry.expires_at = expires_at
        db_entry = existing_entry
    else:
        # Enforce per-vehicle row quota: drop oldest rows if at cap before inserting
        current_count = db.query(func.count(models_db.HistoricalData.id)).filter_by(
            vehicle_id_fk=vehicle_db_obj.id
        ).scalar() or 0
        if current_count >= _MAX_ROWS_PER_VEHICLE:
            oldest = (
                db.query(models_db.HistoricalData)
                .filter_by(vehicle_id_fk=vehicle_db_obj.id)
                .order_by(models_db.HistoricalData.timestamp)
                .limit(max(1, current_count - _MAX_ROWS_PER_VEHICLE + 1))
                .all()
            )
            for old_row in oldest:
                db.delete(old_row)
            logger.warning(
                f"Historical data row cap ({_MAX_ROWS_PER_VEHICLE}) reached for "
                f"{vehicle_db_obj.vehicle_id}. Pruned {len(oldest)} oldest row(s)."
            )

        logger.debug(f"Creating new historical record for {vehicle_db_obj.vehicle_id}, type {record_type}, num {record_number}")
        db_entry = models_db.HistoricalData(
            vehicle_id_fk=vehicle_db_obj.id,
            vehicle_module_id_str=vehicle_db_obj.vehicle_id,
            timestamp=timestamp,
            record_type=record_type,
            record_number=record_number,
            data_payload=data_payload,
            expires_at=expires_at
        )
        db.add(db_entry)

    try:
        db.commit()
    except Exception as e:
        logger.error(f"DB commit error in save_historical_data: {e}", exc_info=True)
        db.rollback()
        return None

    return db_entry

def _historical_data_query(
    db: Session,
    vehicle_id: str,
    record_type_equals: Optional[str] = None,
    record_type_like: Optional[str] = None,
    exclude_record_type_like: Optional[str] = None,
    since_date: Optional[datetime.datetime] = None,
):
    """The shared filter for the three readers below. Unordered and unpaged."""
    query = db.query(models_db.HistoricalData).filter(
        models_db.HistoricalData.vehicle_module_id_str == vehicle_id.upper()
    )
    if record_type_equals:
        # Case-insensitive exact match. Record types are stored mixed case (e.g.
        # "*-LOG-Trip", "XVU-LOG-ChargeCap"), so upper-casing only the parameter
        # would never match them.
        query = query.filter(func.upper(models_db.HistoricalData.record_type) == record_type_equals.upper())
    if record_type_like:
        query = query.filter(models_db.HistoricalData.record_type.ilike(record_type_like))
    if exclude_record_type_like:
        query = query.filter(not_(models_db.HistoricalData.record_type.ilike(exclude_record_type_like)))
    if since_date:
        query = query.filter(models_db.HistoricalData.timestamp > since_date)
    return query


def get_historical_data_for_vehicle(
    db: Session,
    vehicle_id: str,
    record_type_equals: Optional[str] = None,
    record_type_like: Optional[str] = None,
    exclude_record_type_like: Optional[str] = None,
    since_date: Optional[datetime.datetime] = None,
    skip: int = 0,
    limit: Optional[int] = 100,
    sort_ascending: bool = False
) -> List[models_db.HistoricalData]:
    """
    Fetches historical data records for a specific vehicle, with optional filtering.

    Materialises the whole result. Callers that may face an unbounded row count must
    use iter_historical_data_for_vehicle() instead — see its docstring.
    """
    query = _historical_data_query(
        db, vehicle_id, record_type_equals, record_type_like,
        exclude_record_type_like, since_date,
    )

    # Apply sort order
    if sort_ascending:
        query = query.order_by(models_db.HistoricalData.timestamp)
    else:
        query = query.order_by(desc(models_db.HistoricalData.timestamp))

    query = query.offset(skip)
    if limit is not None:
        query = query.limit(limit)

    return query.all()


def count_historical_data_for_vehicle(
    db: Session,
    vehicle_id: str,
    record_type_equals: Optional[str] = None,
    record_type_like: Optional[str] = None,
    exclude_record_type_like: Optional[str] = None,
    since_date: Optional[datetime.datetime] = None,
) -> int:
    """Row count for the same filter, without loading anything."""
    return _historical_data_query(
        db, vehicle_id, record_type_equals, record_type_like,
        exclude_record_type_like, since_date,
    ).count()


def iter_historical_data_for_vehicle(
    db: Session,
    vehicle_id: str,
    record_type_equals: Optional[str] = None,
    record_type_like: Optional[str] = None,
    exclude_record_type_like: Optional[str] = None,
    since_date: Optional[datetime.datetime] = None,
    sort_ascending: bool = False,
    batch_size: int = 200,
):
    """
    Stream the matching records instead of materialising them.

    The V2 app command 32 asks for every record of a type with no limit, and the row
    cap here is 10 000 × 64 KiB — so `.all()` could pull roughly 640 MB of ORM objects
    into memory for a single request, from any authenticated app connection, as often
    as it liked. yield_per() keeps that at one batch regardless of how much history a
    vehicle has accumulated.

    The caller must not detach from the session while iterating, and the surrounding
    transaction stays open for the duration.
    """
    query = _historical_data_query(
        db, vehicle_id, record_type_equals, record_type_like,
        exclude_record_type_like, since_date,
    )
    if sort_ascending:
        query = query.order_by(models_db.HistoricalData.timestamp)
    else:
        query = query.order_by(desc(models_db.HistoricalData.timestamp))

    return query.yield_per(batch_size)

def delete_old_historical_data(db: Session, older_than_days: int = 90) -> int:
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    cutoff_date = now_utc - datetime.timedelta(days=older_than_days)

    # Delete rows that have an explicit past expiry OR have no expiry but are older than cutoff.
    # Crash logs are no longer exempt — they are always saved with a bounded expires_at.
    query = db.query(models_db.HistoricalData).filter(
        or_(
            models_db.HistoricalData.expires_at < now_utc,
            and_(
                models_db.HistoricalData.expires_at == None,
                models_db.HistoricalData.timestamp < cutoff_date
            )
        )
    )

    num_deleted = query.delete(synchronize_session=False)
    db.commit()
    return num_deleted

def get_historical_daily(
    db: Session,
    vehicle_id: str,
    record_type: str = '*-OVM-Utilisation',
    days: int = 90
) -> List[Dict[str, Any]]:
    """
    Fetches historical data grouped by date for a specific vehicle and record type.
    Returns daily aggregated data with concatenated data_payload values.

    Args:
        db: Database session
        vehicle_id: Vehicle ID string
        record_type: Record type to filter (default: '*-OVM-Utilisation')
        days: Number of days to retrieve (default: 90)

    Returns:
        List of dicts with keys: 'u_date' (YYYY-MM-DD), 'data' (concatenated payloads)
    """
    # SQLite and PostgreSQL have different GROUP_CONCAT functions
    # SQLite: GROUP_CONCAT(field)
    # PostgreSQL: STRING_AGG(field, separator)
    # We'll use func.group_concat for SQLite compatibility

    query = db.query(
        func.date(models_db.HistoricalData.timestamp).label('u_date'),
        func.group_concat(models_db.HistoricalData.data_payload).label('data')
    ).filter(
        models_db.HistoricalData.vehicle_module_id_str == vehicle_id.upper(),
        models_db.HistoricalData.record_type == record_type
    ).group_by(
        func.date(models_db.HistoricalData.timestamp)
    ).order_by(
        desc('u_date')
    ).limit(days)

    results = query.all()
    return [{'u_date': str(row.u_date), 'data': row.data} for row in results]

def get_historical_summary(
    db: Session,
    vehicle_id: str,
    since_date: Optional[datetime.datetime] = None
) -> List[Dict[str, Any]]:
    """
    Fetches aggregated statistics about available historical data types for a vehicle.

    Args:
        db: Database session
        vehicle_id: Vehicle ID string
        since_date: Optional datetime to filter records after this date

    Returns:
        List of dicts with keys:
        - 'h_recordtype': Record type
        - 'distinctrecs': Count of distinct record numbers
        - 'totalrecs': Total record count
        - 'totalsize': Total size estimate in bytes
        - 'first': First (minimum) timestamp
        - 'last': Last (maximum) timestamp
    """
    if since_date is None:
        since_date = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)

    # Ensure since_date is timezone-aware
    if since_date.tzinfo is None:
        since_date = since_date.replace(tzinfo=datetime.timezone.utc)

    query = db.query(
        models_db.HistoricalData.record_type.label('h_recordtype'),
        func.count(func.distinct(models_db.HistoricalData.record_number)).label('distinctrecs'),
        func.count(models_db.HistoricalData.id).label('totalrecs'),
        (func.sum(func.length(models_db.HistoricalData.record_type) +
                  func.length(models_db.HistoricalData.data_payload) +
                  func.length(models_db.HistoricalData.vehicle_module_id_str) + 20)).label('totalsize'),
        func.min(models_db.HistoricalData.timestamp).label('first'),
        func.max(models_db.HistoricalData.timestamp).label('last')
    ).filter(
        models_db.HistoricalData.vehicle_module_id_str == vehicle_id.upper(),
        models_db.HistoricalData.timestamp > since_date
    ).group_by(
        models_db.HistoricalData.record_type
    ).order_by(
        models_db.HistoricalData.record_type
    )

    results = query.all()
    return [{
        'h_recordtype': row.h_recordtype,
        'distinctrecs': row.distinctrecs or 0,
        'totalrecs': row.totalrecs or 0,
        'totalsize': row.totalsize or 0,
        'first': row.first.strftime('%Y-%m-%d %H:%M:%S') if row.first else '',
        'last': row.last.strftime('%Y-%m-%d %H:%M:%S') if row.last else ''
    } for row in results]