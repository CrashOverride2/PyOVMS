import logging
import datetime
import time
from typing import Dict, Optional, NamedTuple
from sqlalchemy.orm import Session
from uuid import UUID

from app.config import settings
from app.database import SessionLocal
from app.metrics_manager import metrics_manager
from . import crud
from app.crud import vehicle as vehicle_crud
from app.models import db as ovms_models

logger = logging.getLogger(__name__)

RELEVANT_CHARGE_METRICS = {
    'v.c.charging',
    'v.b.soc',
    'v.c.kwh',
    'v.c.power',
    'v.b.temp'
}

class ActiveChargeSession(NamedTuple):
    charge_log_id: UUID
    vehicle_id: str
    vehicle_db_id: int
    start_time: datetime.datetime
    last_metric_time: datetime.datetime
    last_point_save_time: datetime.datetime
    last_known_kwh: Optional[float]  # Track last non-null v.c.kwh value (energy added)

class ChargeManager:
    """
    A singleton class to manage active vehicle charging sessions.
    """

    # A charge shorter than this is not a charge. Sessions below it are removed again
    # when they close, so a flapping v.c.charging leaves nothing behind.
    MIN_SESSION_DURATION_SECONDS = 60.0

    # And a new session may not open immediately after one closed. Together these
    # bound how fast v.c.charging can be toggled into new rows; before, every flip
    # created a ChargeLog plus points with no limit at all.
    MIN_SESSION_GAP_SECONDS = 30.0

    def __init__(self):
        self.active_sessions: Dict[str, ActiveChargeSession] = {}
        self.vehicle_charge_logging_cache: Dict[str, tuple[int, bool]] = {}
        # vehicle_id -> monotonic timestamp of the last session end, for the gap check.
        self._last_session_end: Dict[str, float] = {}
        logger.info("ChargeManager initialized.")

    def process_metric(self, vehicle_id: str, metric_name: str, value: str, timestamp: datetime.datetime):
        if metric_name not in RELEVANT_CHARGE_METRICS:
            return

        logger.debug(f"ChargeManager processing metric '{metric_name}={value}' for '{vehicle_id}'")

        db = SessionLocal()
        try:
            vehicle_cache_entry = self.vehicle_charge_logging_cache.get(vehicle_id)
            if vehicle_cache_entry is None:
                vehicle = vehicle_crud.get_vehicle_by_vehicle_id(db, vehicle_id)
                if not vehicle:
                    return

                vehicle_cache_entry = (vehicle.id, vehicle.enable_charge_logging)
                self.vehicle_charge_logging_cache[vehicle_id] = vehicle_cache_entry
            else:
                vehicle = None

            vehicle_db_id, enable_charge_logging = vehicle_cache_entry
            if not enable_charge_logging:
                return

            if metric_name == 'v.c.charging':
                is_charging = value and value.lower() in ['yes', 'true', '1']
                session = self.active_sessions.get(vehicle_id)

                if is_charging and not session:
                    # Debounce session creation.
                    #
                    # Every flip of v.c.charging used to create a ChargeLog row plus
                    # points immediately, with no minimum duration, no rate limit and
                    # no per-vehicle ceiling — so alternating yes/no grew the table
                    # without bound. A real charge start is also not something that
                    # happens twice a minute, so refusing to open a new session
                    # straight after the last one closed costs nothing real.
                    last_end = self._last_session_end.get(vehicle_id)
                    if last_end is not None and (time.monotonic() - last_end) < self.MIN_SESSION_GAP_SECONDS:
                        logger.debug(
                            f"Ignoring charge start for {vehicle_id}: previous session "
                            f"ended less than {self.MIN_SESSION_GAP_SECONDS}s ago."
                        )
                        return
                    if vehicle is None:
                        vehicle = vehicle_crud.get_vehicle_by_id(db, vehicle_db_id)
                        if not vehicle:
                            self.vehicle_charge_logging_cache.pop(vehicle_id, None)
                            return
                    self._start_charge_session(db, vehicle, timestamp)
                elif not is_charging and session:
                    self._end_charge_session(db, vehicle_id, timestamp)

            session = self.active_sessions.get(vehicle_id)
            if session:
                self._update_active_session(db, vehicle_id, timestamp)
        finally:
            db.close()

    def _start_charge_session(self, db: Session, vehicle: ovms_models.Vehicle, timestamp: datetime.datetime):
        logger.info(f"Starting new charge session for vehicle {vehicle.vehicle_id}")

        metrics = metrics_manager.get_metrics_for_vehicle(vehicle.vehicle_id) or {}
        start_soc = metrics.get('v.b.soc')
        start_latitude = metrics.get('v.p.latitude')
        start_longitude = metrics.get('v.p.longitude')
        start_odometer = metrics.get('v.p.odometer')

        logger.debug(f"Start session details for {vehicle.vehicle_id}: timestamp={timestamp}, start_soc={start_soc}, "
                     f"latitude={start_latitude}, longitude={start_longitude}, odometer={start_odometer}")

        new_log = crud.create_charge_log(
            db, vehicle_id_fk=vehicle.id, start_time=timestamp,
            start_soc=start_soc, start_latitude=start_latitude,
            start_longitude=start_longitude, start_odometer=start_odometer
        )

        self.active_sessions[vehicle.vehicle_id] = ActiveChargeSession(
            charge_log_id=new_log.id,
            vehicle_id=vehicle.vehicle_id,
            vehicle_db_id=vehicle.id,
            start_time=timestamp,
            last_metric_time=timestamp,
            last_point_save_time=timestamp,
            last_known_kwh=None  # Will be updated during charging
        )
        logger.debug(f"Created ActiveChargeSession in memory for {vehicle.vehicle_id}: {self.active_sessions[vehicle.vehicle_id]}")
        self._save_charge_point(db, new_log.id, timestamp, metrics)

    def _end_charge_session(self, db: Session, vehicle_id: str, timestamp: datetime.datetime):
        session = self.active_sessions.pop(vehicle_id, None)
        if not session:
            logger.debug(f"Attempted to end charge session for {vehicle_id}, but no active session was found.")
            return

        self._last_session_end[vehicle_id] = time.monotonic()

        # Discard sessions too short to be a real charge. Without this, a flapping
        # v.c.charging left a trail of near-empty rows that the statistics and the
        # export then had to carry forever.
        duration = (timestamp - session.start_time).total_seconds()
        if duration < self.MIN_SESSION_DURATION_SECONDS:
            logger.info(
                f"Discarding charge session {session.charge_log_id} for {vehicle_id}: "
                f"{duration:.0f}s is below the {self.MIN_SESSION_DURATION_SECONDS}s minimum."
            )
            try:
                crud.delete_charge_log(db, charge_log_id=session.charge_log_id)
            except Exception as e:
                logger.warning(f"Could not discard short charge session {session.charge_log_id}: {e}")
            return

        logger.info(f"Ending charge session for vehicle {vehicle_id}")
        metrics = metrics_manager.get_metrics_for_vehicle(vehicle_id) or {}
        end_soc = metrics.get('v.b.soc')

        # v.c.kwh resets on charge start and accumulates during charge
        # So the last_known_kwh IS the total energy added
        energy_added = session.last_known_kwh

        if energy_added is not None:
            logger.debug(f"Energy added for session {session.charge_log_id}: {energy_added:.3f} kWh (from last_known_kwh)")
        else:
            logger.warning(f"No energy data available for session {session.charge_log_id}. v.c.kwh was never received during charge.")

        logger.debug(f"End session details for {vehicle_id}: timestamp={timestamp}, end_soc={end_soc}, energy_added_kwh={energy_added}")

        self._save_charge_point(db, session.charge_log_id, timestamp, metrics)
        
        crud.update_charge_log(
            db, charge_log_id=session.charge_log_id, end_time=timestamp, 
            end_soc=end_soc, energy_added_kwh=energy_added
        )
        logger.debug(f"Removed ActiveChargeSession from memory for {vehicle_id}")

    def _update_active_session(self, db: Session, vehicle_id: str, timestamp: datetime.datetime):
        session = self.active_sessions.get(vehicle_id)
        if not session:
            return

        # Get current metrics and update last_known_kwh if available
        metrics = metrics_manager.get_metrics_for_vehicle(vehicle_id) or {}
        current_kwh_str = metrics.get('v.c.kwh')

        # Update last_known_kwh if we have a valid non-null value
        updated_kwh = session.last_known_kwh
        if current_kwh_str is not None:
            try:
                current_kwh = float(current_kwh_str)
                if current_kwh > 0:  # Only update if positive value
                    updated_kwh = current_kwh
                    logger.debug(f"Updated last_known_kwh for {vehicle_id}: {updated_kwh:.3f} kWh")
            except (ValueError, TypeError):
                logger.debug(f"Could not parse v.c.kwh value '{current_kwh_str}' for {vehicle_id}")

        self.active_sessions[vehicle_id] = session._replace(
            last_metric_time=timestamp,
            last_known_kwh=updated_kwh
        )
        logger.debug(f"Updated active session for {vehicle_id}: last_metric_time={timestamp}, last_known_kwh={updated_kwh}")

        time_since_last_save = (timestamp - session.last_point_save_time).total_seconds()
        if time_since_last_save >= 300 and timestamp != session.last_point_save_time:
            logger.debug(f"Saving periodic charge point for {vehicle_id} after {time_since_last_save:.0f} seconds.")
            self._save_charge_point(db, session.charge_log_id, timestamp, metrics)
            self.active_sessions[vehicle_id] = self.active_sessions[vehicle_id]._replace(last_point_save_time=timestamp)

    def _save_charge_point(self, db: Session, charge_log_id: UUID, timestamp: datetime.datetime, metrics: Dict[str, any]):
        soc = metrics.get('v.b.soc')
        power_kw = metrics.get('v.c.power')
        battery_temp = metrics.get('v.b.temp')
        
        logger.debug(f"Saving charge point for log ID {charge_log_id}: ts={timestamp}, soc={soc}, power={power_kw}, temp={battery_temp}")
        
        crud.create_charge_log_point(
            db, charge_log_id_fk=charge_log_id, timestamp=timestamp,
            soc=soc, power_kw=power_kw, battery_temp_c=battery_temp
        )

    def check_for_stale_sessions(self, db: Session):
        now = datetime.datetime.now(datetime.timezone.utc)
        stale_sessions = []
        logger.debug("Running check for stale charge sessions...")
        for vehicle_id, session in self.active_sessions.items():
            idle_time = (now - session.last_metric_time).total_seconds()
            if idle_time > settings.TIMEOUT_CHARGE_IDLE:
                logger.debug(f"Found stale session for {vehicle_id}. Idle for {idle_time:.0f}s (limit: {settings.TIMEOUT_CHARGE_IDLE}s).")
                stale_sessions.append(vehicle_id)
        
        if not stale_sessions:
            logger.debug("No stale sessions found.")

        for vehicle_id in stale_sessions:
            logger.warning(f"Charge session for {vehicle_id} is stale. Ending it due to timeout.")
            self._end_charge_session(db, vehicle_id, self.active_sessions[vehicle_id].last_metric_time)

charge_manager = ChargeManager()
