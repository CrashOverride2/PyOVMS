from sqlalchemy.orm import Session, joinedload
from sqlalchemy import desc, func, extract
from sqlalchemy.exc import IntegrityError
from typing import Optional, List, Tuple
import datetime
from uuid import UUID

from . import models
from app.models import db as ovms_models
from .api_models import ChargeLogSummary, ChargeStatistics, ChargeStatisticsTotals, ChargeStatisticsMonthly
from app.utils.parsing_helpers import _safe_float_parse
import logging

logger = logging.getLogger(__name__)

def check_vehicle_ownership(db: Session, user_id: int, vehicle_id: str) -> bool:
    """
    Checks if a user owns the specified vehicle. Admins have access to all.
    This function uses the main OVMS DB session.
    """
    user = db.query(ovms_models.User).filter(ovms_models.User.id == user_id).first()
    if not user:
        return False
    if user.is_admin:
        return True
    
    vehicle = db.query(ovms_models.Vehicle).filter(
        ovms_models.Vehicle.vehicle_id == vehicle_id.upper(),
        ovms_models.Vehicle.owner_id == user_id
    ).first()
    return vehicle is not None

def create_charge_log(db: Session, vehicle_id_fk: int, start_time: datetime.datetime, start_soc: Optional[float],
                      start_latitude: Optional[float] = None, start_longitude: Optional[float] = None,
                      start_odometer: Optional[float] = None) -> models.ChargeLog:
    db_log = models.ChargeLog(
        vehicle_id_fk=vehicle_id_fk,
        start_time=start_time,
        start_soc=_safe_float_parse(start_soc),
        start_latitude=_safe_float_parse(start_latitude),
        start_longitude=_safe_float_parse(start_longitude),
        start_odometer=_safe_float_parse(start_odometer),
    )
    db.add(db_log)
    db.commit()
    db.refresh(db_log)
    return db_log

def update_charge_log(db: Session, charge_log_id: UUID, end_time: datetime.datetime, end_soc: Optional[float], energy_added_kwh: Optional[float]) -> Optional[models.ChargeLog]:
    db_log = db.query(models.ChargeLog).filter(models.ChargeLog.id == charge_log_id).first()
    if db_log:
        db_log.end_time = end_time
        db_log.end_soc = _safe_float_parse(end_soc)
        db_log.energy_added_kwh = _safe_float_parse(energy_added_kwh)

        power_points_query = db.query(models.ChargeLogPoint.power_kw).filter(
            models.ChargeLogPoint.charge_log_id_fk == charge_log_id,
            models.ChargeLogPoint.power_kw.isnot(None)
        )
        
        power_points = power_points_query.all()
        
        if power_points:
            valid_powers = [p[0] for p in power_points]
            if valid_powers:
                db_log.max_power_kw = max(valid_powers)
                db_log.average_power_kw = sum(valid_powers) / len(valid_powers)

        db.commit()
        db.refresh(db_log)
    return db_log

def create_charge_log_point(db: Session, charge_log_id_fk: UUID, timestamp: datetime.datetime, soc: Optional[float], power_kw: Optional[float], battery_temp_c: Optional[float]):
    db_point = models.ChargeLogPoint(
        charge_log_id_fk=charge_log_id_fk,
        timestamp=timestamp,
        soc=_safe_float_parse(soc),
        power_kw=_safe_float_parse(power_kw),
        battery_temp_c=_safe_float_parse(battery_temp_c),
    )
    db.add(db_point)
    try:
        db.commit()
    except IntegrityError as e:
        db.rollback()
        logger.debug(f"Duplicate charge log point ignored for charge_log_id={charge_log_id_fk} at timestamp={timestamp}: {e}")
        # Silently ignore duplicate entries - this is expected behavior with the unique constraint

def get_charge_logs_for_vehicle(db: Session, vehicle_id: str, limit: int, offset: int) -> Tuple[List[ChargeLogSummary], int]:
    vehicle = db.query(ovms_models.Vehicle).filter(ovms_models.Vehicle.vehicle_id == vehicle_id).first()
    if not vehicle:
        return [], 0

    query = db.query(models.ChargeLog).filter(models.ChargeLog.vehicle_id_fk == vehicle.id)
    total_items = query.count()
    
    logs = query.order_by(desc(models.ChargeLog.start_time)).limit(limit).offset(offset).all()
    
    results = []
    for log in logs:
        duration = (log.end_time - log.start_time).total_seconds() if log.end_time and log.start_time else None
        summary = ChargeLogSummary.from_orm(log)
        summary.duration_seconds = int(duration) if duration is not None else None
        results.append(summary)
        
    return results, total_items

def get_charge_log_details(db: Session, charge_log_id: UUID) -> Optional[models.ChargeLog]:
    return db.query(models.ChargeLog).options(joinedload(models.ChargeLog.points), joinedload(models.ChargeLog.vehicle)).filter(models.ChargeLog.id == charge_log_id).first()

def delete_charge_log(db: Session, charge_log_id: UUID) -> bool:
    """Deletes a charge log and its associated points."""
    db_log = db.query(models.ChargeLog).filter(models.ChargeLog.id == charge_log_id).first()
    if db_log:
        db.delete(db_log)
        db.commit()
        return True
    return False

def export_charge_logs_for_vehicle(db: Session, vehicle_id: str) -> List[models.ChargeLog]:
    vehicle = db.query(ovms_models.Vehicle).filter(ovms_models.Vehicle.vehicle_id == vehicle_id).first()
    if not vehicle:
        return []
    return db.query(models.ChargeLog).filter(models.ChargeLog.vehicle_id_fk == vehicle.id).order_by(desc(models.ChargeLog.start_time)).all()

def get_charge_statistics(db: Session, vehicle_id: str) -> ChargeStatistics:
    vehicle = db.query(ovms_models.Vehicle).filter(ovms_models.Vehicle.vehicle_id == vehicle_id).first()
    
    default_totals = ChargeStatisticsTotals(
        total_charges=0, total_energy_kwh=0, total_duration_seconds=0,
        average_energy_kwh=0, average_duration_seconds=0, total_soc_gained=0, average_soc_gained=0
    )

    if not vehicle:
        return ChargeStatistics(total=default_totals, monthly=[])

    base_query = db.query(models.ChargeLog).filter(
        models.ChargeLog.vehicle_id_fk == vehicle.id,
        models.ChargeLog.end_time.isnot(None)
    )

    total_stats_result = base_query.with_entities(
        func.count(models.ChargeLog.id),
        func.sum(models.ChargeLog.energy_added_kwh),
        func.sum(extract('epoch', models.ChargeLog.end_time) - extract('epoch', models.ChargeLog.start_time)),
        func.sum(models.ChargeLog.end_soc - models.ChargeLog.start_soc)
    ).one_or_none()

    if not total_stats_result or total_stats_result is None:
        return ChargeStatistics(total=default_totals, monthly=[])

    total_charges, total_energy, total_duration, total_soc = total_stats_result
    
    total_charges = total_charges or 0
    total_energy = total_energy or 0.0
    total_duration = int(total_duration or 0)
    total_soc = total_soc or 0.0

    total = ChargeStatisticsTotals(
        total_charges=total_charges,
        total_energy_kwh=total_energy,
        total_duration_seconds=total_duration,
        average_energy_kwh=total_energy / total_charges if total_charges > 0 else 0,
        average_duration_seconds=total_duration // total_charges if total_charges > 0 else 0,
        total_soc_gained=total_soc,
        average_soc_gained=total_soc / total_charges if total_charges > 0 else 0
    )
    
    if db.bind.dialect.name == 'sqlite':
        trunc_func = func.strftime('%Y-%m-01', models.ChargeLog.start_time)
    else:
        trunc_func = func.date_trunc('month', models.ChargeLog.start_time)

    monthly_stats_results = base_query.with_entities(
        trunc_func.label('period'),
        func.count(models.ChargeLog.id).label('total_charges'),
        func.sum(models.ChargeLog.energy_added_kwh).label('total_energy_kwh')
    ).group_by('period').order_by(desc('period')).limit(12).all()

    monthly = []
    for row in monthly_stats_results:
        period_date = None
        if isinstance(row.period, str):
            period_date = datetime.datetime.strptime(row.period, '%Y-%m-%d').date()
        elif isinstance(row.period, datetime.datetime):
            period_date = row.period.date()
        elif isinstance(row.period, datetime.date):
            period_date = row.period
            
        if period_date:
            monthly.append(
                ChargeStatisticsMonthly(
                    period=period_date,
                    total_charges=row.total_charges,
                    total_energy_kwh=row.total_energy_kwh or 0.0
                )
            )

    return ChargeStatistics(total=total, monthly=monthly)