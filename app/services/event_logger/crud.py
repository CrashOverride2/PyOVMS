import datetime
from typing import List, Optional, Tuple
from uuid import UUID

from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.models import db as ovms_models
from . import models


def create_event(db: Session, **fields) -> models.VehicleEvent:
    row = models.VehicleEvent(**fields)
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def update_event(db: Session, event_id: UUID, **fields) -> bool:
    """Write [fields] onto the row; False when the row is gone (deleted from the UI)."""
    count = (
        db.query(models.VehicleEvent)
        .filter(models.VehicleEvent.id == event_id)
        .update(fields, synchronize_session=False)
    )
    db.commit()
    return count > 0


def close_open_event(db: Session, event_id: UUID, **fields) -> bool:
    """Close a row only while it is still open — the orphan pass races nothing then."""
    count = (
        db.query(models.VehicleEvent)
        .filter(models.VehicleEvent.id == event_id, models.VehicleEvent.end_time.is_(None))
        .update(fields, synchronize_session=False)
    )
    db.commit()
    return count > 0


def reopen_event(db: Session, event_id: UUID) -> bool:
    """Take back a row's end (the event went on after a pause shorter than the gap);
    False when the row is gone."""
    count = (
        db.query(models.VehicleEvent)
        .filter(models.VehicleEvent.id == event_id)
        .update({
            models.VehicleEvent.end_time: None,
            models.VehicleEvent.end_soc: None,
            models.VehicleEvent.cabin_temp_end: None,
            models.VehicleEvent.aux_voltage_end: None,
        }, synchronize_session=False)
    )
    db.commit()
    return count > 0


def delete_event(db: Session, event_id: UUID) -> bool:
    row = db.query(models.VehicleEvent).filter(models.VehicleEvent.id == event_id).first()
    if row is None:
        return False
    db.delete(row)
    db.commit()
    return True


def delete_open_event(db: Session, event_id: UUID) -> bool:
    count = (
        db.query(models.VehicleEvent)
        .filter(models.VehicleEvent.id == event_id, models.VehicleEvent.end_time.is_(None))
        .delete(synchronize_session=False)
    )
    db.commit()
    return count > 0


def get_event(db: Session, event_id: UUID) -> Optional[models.VehicleEvent]:
    return db.query(models.VehicleEvent).filter(models.VehicleEvent.id == event_id).first()


def open_events_for_vehicle(db: Session, vehicle_db_id: int) -> List[models.VehicleEvent]:
    return (
        db.query(models.VehicleEvent)
        .filter(models.VehicleEvent.vehicle_id_fk == vehicle_db_id, models.VehicleEvent.end_time.is_(None))
        .order_by(desc(models.VehicleEvent.start_time))
        .all()
    )


def open_event_ids(db: Session) -> List[UUID]:
    return [
        row.id for row in db.query(models.VehicleEvent.id)
        .filter(models.VehicleEvent.end_time.is_(None))
        .order_by(models.VehicleEvent.start_time, models.VehicleEvent.id)
        .all()
    ]


def get_events_for_vehicle(
    db: Session, vehicle_id: str, limit: int, offset: int
) -> Tuple[List[models.VehicleEvent], int]:
    """A page of the vehicle's events, newest start first — the order the app merges
    its timeline in, the same as the charge log's."""
    vehicle = db.query(ovms_models.Vehicle).filter(ovms_models.Vehicle.vehicle_id == vehicle_id).first()
    if not vehicle:
        return [], 0
    query = db.query(models.VehicleEvent).filter(models.VehicleEvent.vehicle_id_fk == vehicle.id)
    total = query.count()
    rows = (
        query.order_by(desc(models.VehicleEvent.start_time), desc(models.VehicleEvent.id))
        .offset(offset)
        .limit(limit)
        .all()
    )
    return rows, total


def vehicle_id_of(db: Session, event: models.VehicleEvent) -> Optional[str]:
    vehicle = db.query(ovms_models.Vehicle).filter(ovms_models.Vehicle.id == event.vehicle_id_fk).first()
    return vehicle.vehicle_id if vehicle else None


def duration_seconds(event: models.VehicleEvent) -> Optional[int]:
    if event.start_time is None or event.end_time is None:
        return None
    start = event.start_time
    end = event.end_time
    if start.tzinfo is None:
        start = start.replace(tzinfo=datetime.timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=datetime.timezone.utc)
    return int((end - start).total_seconds())
