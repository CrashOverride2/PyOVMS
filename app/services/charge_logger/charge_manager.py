import logging
import datetime
import threading
import time
from typing import Dict, Optional, NamedTuple
from sqlalchemy.orm import Session
from uuid import UUID

from app.config import settings
from app.database import SessionLocal
from app.metrics_manager import metrics_manager
from app.utils.timestamps import as_utc
from sqlalchemy import func
from . import crud, models
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
    # False for a session resumed from the broker's retained burst until the vehicle
    # is heard live. Retained values say what the module last published, not when, so
    # such a session has nothing after its last stored point; if it goes stale like
    # that it is closed as the orphan it still is (`_close_open_row`).
    heard_live: bool = True

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

    # The resume window is measured on the message timestamp, which is server time
    # corrected by the vehicle's clock offset (`MqttMetricsSubscriber._resolve_timestamp`),
    # while the orphan close runs on server time alone. Closing only past the idle limit
    # *plus* the largest offset the subscriber accepts keeps a row out of the close for
    # as long as any message could still resume it. Mirrors
    # `MqttMetricsSubscriber.MAX_VEHICLE_CLOCK_SKEW_SECONDS`; not imported, because that
    # module imports this one (a test keeps the two equal).
    ORPHAN_CLOCK_MARGIN_SECONDS = 300

    def __init__(self):
        self.active_sessions: Dict[str, ActiveChargeSession] = {}
        self.vehicle_charge_logging_cache: Dict[str, tuple[int, bool]] = {}
        # vehicle_id -> monotonic timestamp of the last session end, for the gap check.
        self._last_session_end: Dict[str, float] = {}
        # Guards active_sessions and every decision taken on it. They are reached from
        # paho's network thread (V3), the event loop (V2), the housekeeping pass on the
        # threadpool and the API's threadpool. Unlocked, the pass could read a row as
        # unheld, a retained `v.c.charging=yes` resume it, and the pass then delete it
        # under the live session — whose every later point failed its foreign key — and
        # a list request iterating the dict while it changed raised. Reentrant because
        # the stale check ends sessions through the same methods process_metric uses.
        # Held across the per-metric database writes, which already run on those
        # threads; the housekeeping pass takes it per row, never for the whole pass.
        self._lock = threading.RLock()
        logger.info("ChargeManager initialized.")

    def process_metric(self, vehicle_id: str, metric_name: str, value: str, timestamp: datetime.datetime,
                       retained: bool = False):
        """Feed one metric. `retained` marks a broker-retained MQTT message: its value is
        the module's last publish, but its time is unknown, so it moves no clock."""
        if metric_name not in RELEVANT_CHARGE_METRICS:
            return

        logger.debug(f"ChargeManager processing metric '{metric_name}={value}' for '{vehicle_id}'")

        with self._lock:
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
                        self._start_charge_session(db, vehicle, timestamp, retained)
                    elif not is_charging and session:
                        self._end_charge_session(db, vehicle_id, timestamp)

                session = self.active_sessions.get(vehicle_id)
                if session:
                    self._update_active_session(db, vehicle_id, timestamp, retained)
            finally:
                db.close()

    def is_session_active(self, charge_log_id: UUID) -> bool:
        """Whether this process is recording the session right now.

        `end_time IS NULL` alone does not say that: a row is written open and only
        closed by this in-memory manager, so a restart mid-charge leaves one open with
        nobody holding it. The server runs one worker (`run.py`), so this process is
        the only one that could.
        """
        with self._lock:
            return any(s.charge_log_id == charge_log_id for s in list(self.active_sessions.values()))

    def _held_charge_log_ids(self) -> set:
        with self._lock:
            return {s.charge_log_id for s in list(self.active_sessions.values())}

    @staticmethod
    def _last_point(db: Session, charge_log_id: UUID) -> Optional[models.ChargeLogPoint]:
        return (
            db.query(models.ChargeLogPoint)
            .filter(models.ChargeLogPoint.charge_log_id_fk == charge_log_id)
            .order_by(models.ChargeLogPoint.timestamp.desc())
            .first()
        )

    def _adopt_open_session(self, db: Session, vehicle: ovms_models.Vehicle,
                            timestamp: datetime.datetime, retained: bool = False) -> bool:
        """Resume the vehicle's open row instead of opening a second one.

        A restart mid-charge loses the in-memory session while the row stays open, and
        the module's retained `v.c.charging=yes` arrives again on reconnect. Opening a
        new row then split one charge in two — the first closed at whatever point it
        had, the second starting mid-charge. Within `TIMEOUT_CHARGE_IDLE` of its last
        point the row is the same charge by the rule the live session itself follows
        (an idle session is only ended past that limit), so it is taken over.

        Resumed from the retained burst — what a restart delivers — the session's clock
        stays at the row's last point: nothing says the module has been heard since.
        Stamped with the arrival of that burst instead, a module that went offline
        mid-charge was ended at the restart, stretching the charge over the downtime.
        Runs under `_lock` (from process_metric), so the housekeeping pass cannot close
        or delete the row between the check below and the take-over.
        """
        held = self._held_charge_log_ids()
        open_logs = (
            db.query(models.ChargeLog)
            .filter(models.ChargeLog.vehicle_id_fk == vehicle.id, models.ChargeLog.end_time.is_(None))
            .order_by(models.ChargeLog.start_time.desc())
            .all()
        )
        now = as_utc(timestamp)
        for log in open_logs:
            if log.id in held:
                continue
            last_point = self._last_point(db, log.id)
            last_activity = as_utc(last_point.timestamp if last_point else log.start_time)
            if (now - last_activity).total_seconds() > settings.TIMEOUT_CHARGE_IDLE:
                # Too old to be this charge; the housekeeping pass closes it.
                return False
            start_time = as_utc(log.start_time)
            self.active_sessions[vehicle.vehicle_id] = ActiveChargeSession(
                charge_log_id=log.id,
                vehicle_id=vehicle.vehicle_id,
                vehicle_db_id=vehicle.id,
                start_time=start_time,
                last_metric_time=last_activity if retained else timestamp,
                last_point_save_time=last_activity,
                # v.c.kwh counts from the start of the charge, so its next value
                # restores this.
                last_known_kwh=None,
                heard_live=not retained,
            )
            logger.info(f"Resuming open charge session {log.id} for vehicle {vehicle.vehicle_id}"
                        f"{' from retained values' if retained else ''}")
            return True
        return False

    def _start_charge_session(self, db: Session, vehicle: ovms_models.Vehicle, timestamp: datetime.datetime,
                              retained: bool = False):
        if self._adopt_open_session(db, vehicle, timestamp, retained):
            return
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

    def _update_active_session(self, db: Session, vehicle_id: str, timestamp: datetime.datetime,
                               retained: bool = False):
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

        if retained:
            # The value counts (the retained v.c.kwh is this charge's total so far), the
            # arrival time does not: it is when the broker handed the message over, not
            # when the module said it. Neither the idle clock nor a point may move on it.
            self.active_sessions[vehicle_id] = session._replace(last_known_kwh=updated_kwh)
            return

        self.active_sessions[vehicle_id] = session._replace(
            last_metric_time=timestamp,
            last_known_kwh=updated_kwh,
            heard_live=True,
        )
        logger.debug(f"Updated active session for {vehicle_id}: last_metric_time={timestamp}, last_known_kwh={updated_kwh}")

        time_since_last_save = (timestamp - session.last_point_save_time).total_seconds()
        if time_since_last_save >= 300 and timestamp != session.last_point_save_time:
            logger.debug(f"Saving periodic charge point for {vehicle_id} after {time_since_last_save:.0f} seconds.")
            if not self._save_charge_point(db, session.charge_log_id, timestamp, metrics):
                # The row is gone (deleted from the UI, or by anything else): every
                # further point would fail the same way, so the session goes with it.
                logger.warning(f"Charge log {session.charge_log_id} of {vehicle_id} no longer exists; dropping the session.")
                self.active_sessions.pop(vehicle_id, None)
                return
            self.active_sessions[vehicle_id] = self.active_sessions[vehicle_id]._replace(last_point_save_time=timestamp)

    def _save_charge_point(self, db: Session, charge_log_id: UUID, timestamp: datetime.datetime,
                           metrics: Dict[str, any]) -> bool:
        soc = metrics.get('v.b.soc')
        power_kw = metrics.get('v.c.power')
        battery_temp = metrics.get('v.b.temp')
        
        logger.debug(f"Saving charge point for log ID {charge_log_id}: ts={timestamp}, soc={soc}, power={power_kw}, temp={battery_temp}")
        
        return crud.create_charge_log_point(
            db, charge_log_id_fk=charge_log_id, timestamp=timestamp,
            soc=soc, power_kw=power_kw, battery_temp_c=battery_temp
        )

    def check_for_stale_sessions(self, db: Session):
        """End the held sessions that went quiet, then close the orphans; return how
        many rows nobody was recording were closed or dropped.

        Each session is re-checked under the lock before it is ended — a metric may
        have arrived since the list was made — and each is its own try: one that fails
        must not leave the rest open until the next pass.
        """
        now = datetime.datetime.now(datetime.timezone.utc)
        logger.debug("Running check for stale charge sessions...")
        with self._lock:
            stale_sessions = [
                vehicle_id for vehicle_id, session in list(self.active_sessions.items())
                if (now - session.last_metric_time).total_seconds() > settings.TIMEOUT_CHARGE_IDLE
            ]

        if not stale_sessions:
            logger.debug("No stale sessions found.")

        closed = 0
        for vehicle_id in sorted(stale_sessions):
            with self._lock:
                session = self.active_sessions.get(vehicle_id)
                if session is None:
                    continue
                idle_time = (now - session.last_metric_time).total_seconds()
                if idle_time <= settings.TIMEOUT_CHARGE_IDLE:
                    continue
                try:
                    if session.heard_live:
                        logger.warning(f"Charge session for {vehicle_id} is stale (idle {idle_time:.0f}s). Ending it due to timeout.")
                        self._end_charge_session(db, vehicle_id, session.last_metric_time)
                    else:
                        # Resumed from retained values and never heard since: the module
                        # went offline before the restart, and all there is of the
                        # charge is what the row already holds.
                        logger.warning(f"Resumed charge session for {vehicle_id} was never heard live; closing it as an orphan.")
                        self.active_sessions.pop(vehicle_id, None)
                        self._last_session_end[vehicle_id] = time.monotonic()
                        if self._close_open_row(db, session.charge_log_id):
                            closed += 1
                except Exception as e:
                    logger.error(f"Could not end stale charge session for {vehicle_id}: {e}", exc_info=True)
                    db.rollback()

        return closed + self.close_orphaned_sessions(db, now=now)

    def close_orphaned_sessions(self, db: Session, now: Optional[datetime.datetime] = None) -> int:
        """Close the open rows no session holds; return how many were closed or dropped.

        Only this in-memory manager ever closes a row, so a restart mid-charge — or a
        vehicle whose charge ended while the server was down — left `end_time` NULL
        for good, and the row read as a charge in progress forever. A row is only
        touched once its last point is older than `TIMEOUT_CHARGE_IDLE` plus
        `ORPHAN_CLOCK_MARGIN_SECONDS`: inside the idle limit it may still be resumed
        when the vehicle reports charging again (`_adopt_open_session`, which measures
        on the vehicle-corrected message clock — hence the margin), and the idle limit
        is the one after which a held session is ended as stale. How it ends is
        `_close_open_row`.

        Each row is decided and written under the lock, with the held set read again
        right there: a snapshot taken once for the whole pass let a resume in between
        be followed by the close of the row it had just taken over. Each row is its own
        try, in start order, so a row that fails cannot keep the ones after it open on
        every later pass.
        """
        now = as_utc(now or datetime.datetime.now(datetime.timezone.utc))
        limit = settings.TIMEOUT_CHARGE_IDLE + self.ORPHAN_CLOCK_MARGIN_SECONDS
        open_ids = [
            row.id for row in db.query(models.ChargeLog.id)
            .filter(models.ChargeLog.end_time.is_(None))
            .order_by(models.ChargeLog.start_time, models.ChargeLog.id)
            .all()
        ]
        closed = 0
        for log_id in open_ids:
            with self._lock:
                if log_id in self._held_charge_log_ids():
                    continue
                try:
                    last_point = self._last_point(db, log_id)
                    if last_point is not None:
                        last_activity = as_utc(last_point.timestamp)
                    else:
                        log = db.query(models.ChargeLog).filter(models.ChargeLog.id == log_id).first()
                        if log is None:
                            continue
                        last_activity = as_utc(log.start_time)
                    if (now - last_activity).total_seconds() <= limit:
                        continue
                    if self._close_open_row(db, log_id):
                        closed += 1
                except Exception as e:
                    logger.error(f"Could not close orphaned charge session {log_id}: {e}", exc_info=True)
                    db.rollback()
        return closed

    def _close_open_row(self, db: Session, charge_log_id: UUID) -> bool:
        """End an open row nobody records at the end of its record; True if it changed.

        It ends where its record ends — the last point — with that point's SOC. Energy
        comes from `v.c.kwh`, which was only ever kept in memory, so it stays unknown
        rather than guessed; the power figures are computed from the points as for any
        session.

        A row needs at least two points spanning `MIN_SESSION_DURATION_SECONDS` to be a
        charge; anything less is discarded. No point means it never got going, and a
        single point is one reading with no duration and nothing to say where the
        charge got to — not a charge log anyone can use, even when it was the start of
        a real charge cut off by a crash. Several points close together are what a
        flapping `v.c.charging` leaves, discarded as on a live end.

        Both writes are conditional on the row still being open (`crud.*_open_*`).
        """
        log = db.query(models.ChargeLog).filter(models.ChargeLog.id == charge_log_id).first()
        if log is None or log.end_time is not None:
            return False
        point_count = db.query(func.count(models.ChargeLogPoint.id)).filter(
            models.ChargeLogPoint.charge_log_id_fk == charge_log_id
        ).scalar() or 0
        last_point = self._last_point(db, charge_log_id)
        start_time = as_utc(log.start_time)
        end_time = as_utc(last_point.timestamp) if last_point else start_time

        if point_count < 2 or (end_time - start_time).total_seconds() < self.MIN_SESSION_DURATION_SECONDS:
            logger.info(f"Discarding orphaned charge session {charge_log_id}: too short to be a charge.")
            return crud.delete_open_charge_log(db, charge_log_id)

        logger.warning(f"Closing orphaned charge session {charge_log_id} at its last point ({end_time.isoformat()}).")
        return crud.close_open_charge_log(
            db, charge_log_id=charge_log_id, end_time=end_time,
            end_soc=last_point.soc,
            energy_added_kwh=None,
        )

charge_manager = ChargeManager()
