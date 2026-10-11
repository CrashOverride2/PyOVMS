"""
Climate and 12 V events of a parked vehicle, recognised from standard metrics.

  * climate: `v.e.hvac`, `v.e.heating` or `v.e.cooling` coming on while the vehicle is
    off and not charging;
  * 12 V: `v.e.charging12v` coming on under the same conditions with no climate.

Overlapping climate and 12 V charging are one climate event with `aux_charged`, so an
event only opens on a rising edge. The module's `vehicle.charge.12v.start`/`.stop`
events refine the timing where they arrive; duplicates within `EVENT_DEDUP_SECONDS`
are dropped. V2 carries none of these metrics.
"""

import datetime
import logging
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Set, Tuple
from uuid import UUID

from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal
from app.metrics_manager import metrics_manager
from app.crud import vehicle as vehicle_crud
from app.utils.timestamps import as_utc
from . import crud, models

logger = logging.getLogger(__name__)

CLIMATE_METRICS = ('v.e.hvac', 'v.e.heating', 'v.e.cooling')
AUX_METRIC = 'v.e.charging12v'
AUX_POWER_METRIC = 'v.c.12v.power'
STATE_METRICS = {'v.e.on', 'v.c.charging', AUX_METRIC, *CLIMATE_METRICS}
RELEVANT_EVENT_METRICS = STATE_METRICS | {AUX_POWER_METRIC}

EVENT_AUX_START = 'vehicle.charge.12v.start'
EVENT_AUX_STOP = 'vehicle.charge.12v.stop'
RELEVANT_EVENTS = {EVENT_AUX_START, EVENT_AUX_STOP}


def _truthy(value) -> bool:
    return value is not None and str(value).strip().lower() in ('yes', 'true', '1', 'on')


def _float(value) -> Optional[float]:
    try:
        return float(value) if value is not None and str(value).strip() != '' else None
    except (TypeError, ValueError):
        return None


@dataclass
class _VehicleState:
    climate: Optional[bool] = None
    aux: Optional[bool] = None
    # The 12 V state an event announced, until the metric catches up with it.
    aux_from_event: Optional[bool] = None
    last_power: Optional[Tuple[float, datetime.datetime]] = None
    # `v.e.on` and `v.c.charging` as last sent; `metrics_manager` drops values not
    # updated for hours.
    on: Optional[bool] = None
    charging: Optional[bool] = None
    # The climate metrics and `v.e.charging12v` as last sent, for the same reason.
    seen: Dict[str, bool] = field(default_factory=dict)


@dataclass
class ActiveVehicleEvent:
    event_id: UUID
    vehicle_id: str
    vehicle_db_id: int
    kind: str
    start_time: datetime.datetime
    last_activity: datetime.datetime
    last_activity_written: datetime.datetime
    aux_charged: bool = False
    aux_energy_wh: Optional[float] = None
    sources: Set[str] = field(default_factory=set)


class EventManager:
    # Below this an event is a flicker of a metric, not something the car did.
    MIN_EVENT_DURATION_SECONDS = 60.0
    # A new event may not open right after one closed.
    MIN_EVENT_GAP_SECONDS = 30.0
    # The legacy and the MQTT-style topic of one module event arrive back to back.
    EVENT_DEDUP_SECONDS = 5.0
    # How often an open row's `last_activity` is written while it runs.
    ACTIVITY_WRITE_INTERVAL_SECONDS = 300.0
    # The vehicle's charge-logging switch is re-read after this, so turning it on in
    # the web UI takes effect without a restart.
    ENABLED_CACHE_SECONDS = 60.0
    # An integration step longer than this is a gap in the data, not a constant load.
    MAX_POWER_STEP_SECONDS = 900.0
    # Same margin as the charge log's orphan close (the vehicle-corrected clock).
    ORPHAN_CLOCK_MARGIN_SECONDS = 300

    def __init__(self):
        self.active: Dict[str, ActiveVehicleEvent] = {}
        self._states: Dict[str, _VehicleState] = {}
        self._enabled_cache: Dict[str, Tuple[int, bool, float]] = {}
        # vehicle_id -> the last event kept; a rising edge within MIN_EVENT_GAP_SECONDS of
        # it reopens that row.
        self._last_closed: Dict[str, ActiveVehicleEvent] = {}
        self._recent_events: Dict[Tuple[str, str], float] = {}
        # Reached from paho's thread, the housekeeping pass and the API threadpool, as
        # the charge manager is; the same reasoning applies (see `ChargeManager`).
        self._lock = threading.RLock()

    # ---- input ---------------------------------------------------------------------

    def process_metric(self, vehicle_id: str, metric_name: str, value, timestamp: datetime.datetime,
                       retained: bool = False):
        """Feed one metric (already stored in `metrics_manager`). A retained message
        says what the module last published, not when: it may resume an open row but
        never opens one, and it moves no clock."""
        if metric_name not in RELEVANT_EVENT_METRICS:
            active = self.active.get(vehicle_id)
            if active is not None and not retained:
                with self._lock:
                    if self._enabled(vehicle_id) is None:
                        self._end_disabled(vehicle_id)
                    else:
                        self._heard(vehicle_id, timestamp)
            return
        with self._lock:
            state = self._states.setdefault(vehicle_id, _VehicleState())
            if metric_name == 'v.e.on':
                state.on = _truthy(value)
            elif metric_name == 'v.c.charging':
                state.charging = _truthy(value)
            elif metric_name in CLIMATE_METRICS or metric_name == AUX_METRIC:
                state.seen[metric_name] = _truthy(value)
            enabled = self._enabled(vehicle_id)
            if enabled is None:
                self._end_disabled(vehicle_id)
                return
            vehicle_db_id = enabled
            if metric_name == AUX_METRIC and not retained:
                # The metric is the newer word now.
                state.aux_from_event = None
            if metric_name == AUX_POWER_METRIC:
                self._integrate_power(vehicle_id, state, value, timestamp, retained)
                return
            self._evaluate_safely(vehicle_id, vehicle_db_id, timestamp, retained, 'metric')

    @staticmethod
    def wants_event(event_name: str) -> bool:
        return event_name in RELEVANT_EVENTS

    def process_event(self, vehicle_id: str, event_name: str, timestamp: datetime.datetime):
        """Feed one module event, from either of its two topics."""
        if event_name not in RELEVANT_EVENTS:
            return
        with self._lock:
            key = (vehicle_id, event_name)
            now = time.monotonic()
            seen = self._recent_events.get(key)
            if seen is not None and now - seen < self.EVENT_DEDUP_SECONDS:
                return
            self._recent_events[key] = now
            enabled = self._enabled(vehicle_id)
            if enabled is None:
                self._end_disabled(vehicle_id)
                return
            state = self._states.setdefault(vehicle_id, _VehicleState())
            state.aux_from_event = event_name == EVENT_AUX_START
            self._evaluate_safely(vehicle_id, enabled, timestamp, False, 'event')

    def _evaluate_safely(self, vehicle_id: str, vehicle_db_id: int,
                         timestamp: datetime.datetime, retained: bool, source: str):
        """`_evaluate` in a session of its own. A database error must not use up the
        edge it was recording: the states go back to what they were, so the next
        message sees the same change again instead of a level with no edge left."""
        state = self._states.setdefault(vehicle_id, _VehicleState())
        before = (state.climate, state.aux)
        db = SessionLocal()
        try:
            self._evaluate(db, vehicle_id, vehicle_db_id, timestamp, retained, source)
        except Exception as e:
            state.climate, state.aux = before
            db.rollback()
            logger.error(f"Vehicle event of {vehicle_id} could not be recorded: {e}", exc_info=True)
        finally:
            db.close()

    def _end_disabled(self, vehicle_id: str):
        """Charge logging was switched off (or the vehicle is gone) while an event
        ran: it ends at the last time it was heard. Left open, every further message
        kept it fresh, and it stayed "in progress" — and undeletable — for good."""
        active = self.active.get(vehicle_id)
        if active is None:
            return
        db = SessionLocal()
        try:
            self._end(db, vehicle_id, active.last_activity)
        except Exception as e:
            db.rollback()
            self.active.pop(vehicle_id, None)
            logger.error(f"Could not end vehicle event of {vehicle_id}: {e}", exc_info=True)
        finally:
            db.close()

    # ---- the state machine ---------------------------------------------------------

    def _evaluate(self, db: Session, vehicle_id: str, vehicle_db_id: int,
                  timestamp: datetime.datetime, retained: bool, source: str):
        metrics = metrics_manager.get_metrics_for_vehicle(vehicle_id) or {}
        state = self._states.setdefault(vehicle_id, _VehicleState())

        parked = not (state.on if state.on is not None else _truthy(metrics.get('v.e.on')))
        hv_charging = (state.charging if state.charging is not None
                       else _truthy(metrics.get('v.c.charging')))
        def level(name: str) -> bool:
            seen = state.seen.get(name)
            return seen if seen is not None else _truthy(metrics.get(name))

        climate = any(level(name) for name in CLIMATE_METRICS)
        aux = state.aux_from_event if state.aux_from_event is not None else level(AUX_METRIC)

        # A first value seen live counts as a change; one from the retained burst does
        # not, since nothing says when it came on.
        climate_rose = climate and (state.climate is False or (state.climate is None and not retained))
        aux_rose = aux and (state.aux is False or (state.aux is None and not retained))
        # Only a state never seen since the start may be the open row's own, still
        # running: one seen off has ended, and what rises now is a new event.
        climate_unseen = state.climate is None
        aux_unseen = state.aux is None
        state.climate, state.aux = climate, aux

        active = self.active.get(vehicle_id)
        if active is not None and not retained:
            self._heard(vehicle_id, timestamp)
        # A retained value is the module's last publish, not when it happened: what it
        # ends, ends when the vehicle was last heard, not at the arrival of the burst.
        end_at = active.last_activity if (active is not None and retained) else timestamp

        if not parked or hv_charging:
            # Driving and charging are entries of their own on the timeline.
            if active is not None:
                self._end(db, vehicle_id, end_at)
            return

        if active is None:
            if climate and (climate_rose or retained):
                self._open(db, vehicle_id, vehicle_db_id, models.KIND_CLIMATE, timestamp,
                           retained, aux_charged=aux, source=source, fresh=climate_rose,
                           may_adopt=retained or climate_unseen)
            elif aux and not climate and (aux_rose or retained):
                self._open(db, vehicle_id, vehicle_db_id, models.KIND_AUX_CHARGE, timestamp,
                           retained, aux_charged=True, source=source, fresh=aux_rose,
                           may_adopt=retained or aux_unseen)
            return

        active.sources.add(source)
        if active.kind == models.KIND_AUX_CHARGE:
            if climate:
                # The converter came first and the heating followed: one event.
                active.kind = models.KIND_CLIMATE
                active.aux_charged = True
                self._write(db, vehicle_id, kind=models.KIND_CLIMATE, aux_charged=True,
                            source=self._source_label(active))
            elif not aux:
                self._end(db, vehicle_id, end_at)
            return

        # A climate event.
        if aux and not active.aux_charged:
            active.aux_charged = True
            self._write(db, vehicle_id, aux_charged=True, source=self._source_label(active))
        if not climate:
            # The converter's run-on is this event's tail: the 12 V that stays on has
            # no rising edge left to open a boost with.
            self._end(db, vehicle_id, end_at)

    def _open(self, db: Session, vehicle_id: str, vehicle_db_id: int, kind: str,
              timestamp: datetime.datetime, retained: bool, aux_charged: bool, source: str,
              fresh: bool, may_adopt: bool):
        if may_adopt and self._adopt(db, vehicle_id, vehicle_db_id, kind, timestamp, retained):
            return
        if retained or not fresh:
            return
        if not may_adopt:
            # Seen off since the start: close an unheld open row at its last activity.
            self._close_unheld(db, vehicle_db_id)
        last = self._last_closed.get(vehicle_id)
        if last is not None and 0 <= (as_utc(timestamp) - last.last_activity).total_seconds() < self.MIN_EVENT_GAP_SECONDS:
            # Off and on again within the gap is one event.
            self._reopen(db, vehicle_id, last, kind, aux_charged, source)
            return

        metrics = metrics_manager.get_metrics_for_vehicle(vehicle_id) or {}
        row = crud.create_event(
            db,
            vehicle_id_fk=vehicle_db_id,
            kind=kind,
            start_time=timestamp,
            last_activity=timestamp,
            start_soc=_float(metrics.get('v.b.soc')),
            latitude=_float(metrics.get('v.p.latitude')),
            longitude=_float(metrics.get('v.p.longitude')),
            cabin_temp_start=_float(metrics.get('v.e.cabintemp')),
            cabin_setpoint=_float(metrics.get('v.e.cabinsetpoint')),
            ambient_temp=_float(metrics.get('v.e.temp')),
            aux_charged=aux_charged,
            aux_voltage_start=_float(metrics.get('v.b.12v.voltage')),
            source=source,
        )
        self.active[vehicle_id] = ActiveVehicleEvent(
            event_id=row.id, vehicle_id=vehicle_id, vehicle_db_id=vehicle_db_id, kind=kind,
            start_time=timestamp, last_activity=timestamp, last_activity_written=timestamp,
            aux_charged=aux_charged, sources={source},
        )
        state = self._states.get(vehicle_id)
        if state is not None:
            state.last_power = None
        logger.info(f"Vehicle event {kind} started for {vehicle_id} ({source}).")

    def _reopen(self, db: Session, vehicle_id: str, last: ActiveVehicleEvent, kind: str,
                aux_charged: bool, source: str):
        """Hold the event that ended moments ago again, its end taken back."""
        self._last_closed.pop(vehicle_id, None)
        if last.event_id in self._held_ids():
            return
        if not crud.reopen_event(db, last.event_id):
            # Deleted meanwhile (from the UI): nothing to continue, nothing to open
            # either — the next rising edge past the gap is a new event.
            return
        if kind == models.KIND_CLIMATE:
            last.kind = models.KIND_CLIMATE
        last.aux_charged = last.aux_charged or aux_charged
        last.sources.add(source)
        self.active[vehicle_id] = last
        self._write(db, vehicle_id, kind=last.kind, aux_charged=last.aux_charged,
                    source=self._source_label(last))
        logger.info(f"Vehicle event {last.event_id} of {vehicle_id} continues after a short pause.")

    def _adopt(self, db: Session, vehicle_id: str, vehicle_db_id: int, kind: str,
               timestamp: datetime.datetime, retained: bool) -> bool:
        """Resume the vehicle's open row after a restart rather than open a second one —
        within the idle limit of its last activity it is the same event."""
        held = self._held_ids()
        now = as_utc(timestamp)
        # Newest first: an older open row is the orphan pass's.
        for row in crud.open_events_for_vehicle(db, vehicle_db_id):
            if row.id in held:
                continue
            last = as_utc(row.last_activity or row.start_time)
            if (now - last).total_seconds() > settings.TIMEOUT_CHARGE_IDLE:
                return False
            if row.kind != kind and kind != models.KIND_CLIMATE:
                # A climate row is not resumed as a boost; the reverse is the upgrade.
                return False
            self.active[vehicle_id] = ActiveVehicleEvent(
                event_id=row.id, vehicle_id=vehicle_id, vehicle_db_id=vehicle_db_id,
                kind=row.kind, start_time=as_utc(row.start_time),
                last_activity=last if retained else timestamp,
                last_activity_written=last,
                aux_charged=bool(row.aux_charged),
                aux_energy_wh=row.aux_energy_wh,
                sources=set((row.source or 'metric').replace('both', 'metric event').split()),
            )
            logger.info(f"Resuming open vehicle event {row.id} for {vehicle_id}.")
            if kind == models.KIND_CLIMATE and row.kind == models.KIND_AUX_CHARGE:
                # A resumed boost running with the heating is upgraded to climate at once.
                active = self.active[vehicle_id]
                active.kind = models.KIND_CLIMATE
                active.aux_charged = True
                self._write(db, vehicle_id, kind=models.KIND_CLIMATE, aux_charged=True)
            return True
        return False

    def _close_unheld(self, db: Session, vehicle_db_id: int):
        held = self._held_ids()
        for row in crud.open_events_for_vehicle(db, vehicle_db_id):
            if row.id in held:
                continue
            self._close_row_at_last_activity(db, row)

    def _close_row_at_last_activity(self, db: Session, row) -> bool:
        start = as_utc(row.start_time)
        last = as_utc(row.last_activity or row.start_time)
        if (last - start).total_seconds() < self.MIN_EVENT_DURATION_SECONDS:
            return crud.delete_open_event(db, row.id)
        return crud.close_open_event(db, row.id, end_time=last)

    def _end(self, db: Session, vehicle_id: str, timestamp: datetime.datetime):
        active = self.active.pop(vehicle_id, None)
        if active is None:
            return
        end = max(as_utc(timestamp), active.start_time)
        duration = (end - active.start_time).total_seconds()
        if duration < self.MIN_EVENT_DURATION_SECONDS:
            # A discarded flicker sets no gap: it used to block the real event that
            # followed it within MIN_EVENT_GAP_SECONDS.
            logger.info(f"Discarding vehicle event {active.event_id} of {vehicle_id}: {duration:.0f}s.")
            try:
                crud.delete_event(db, active.event_id)
            except Exception as e:
                db.rollback()
                logger.warning(f"Could not discard short vehicle event {active.event_id}: {e}")
            return
        metrics = metrics_manager.get_metrics_for_vehicle(vehicle_id) or {}
        crud.close_open_event(
            db, active.event_id,
            end_time=end,
            last_activity=end,
            end_soc=_float(metrics.get('v.b.soc')),
            cabin_temp_end=_float(metrics.get('v.e.cabintemp')),
            aux_voltage_end=_float(metrics.get('v.b.12v.voltage')),
            aux_charged=active.aux_charged,
            aux_energy_wh=round(active.aux_energy_wh, 1) if active.aux_energy_wh is not None else None,
            kind=active.kind,
            source=self._source_label(active),
        )
        active.last_activity = end
        self._last_closed[vehicle_id] = active
        logger.info(f"Vehicle event {active.kind} ended for {vehicle_id} after {duration:.0f}s.")

    def _heard(self, vehicle_id: str, timestamp: datetime.datetime):
        active = self.active.get(vehicle_id)
        if active is None:
            return
        if timestamp > active.last_activity:
            active.last_activity = timestamp
        if (active.last_activity - active.last_activity_written).total_seconds() >= self.ACTIVITY_WRITE_INTERVAL_SECONDS:
            db = SessionLocal()
            try:
                if not crud.update_event(db, active.event_id, last_activity=active.last_activity):
                    # Deleted from the UI: the event goes with it.
                    self.active.pop(vehicle_id, None)
                    return
                active.last_activity_written = active.last_activity
            finally:
                db.close()

    def _integrate_power(self, vehicle_id: str, state: _VehicleState, value,
                         timestamp: datetime.datetime, retained: bool):
        watts = _float(value)
        if retained or watts is None:
            return
        active = self.active.get(vehicle_id)
        previous = state.last_power
        state.last_power = (abs(watts), timestamp)
        if active is None or previous is None:
            return
        prev_watts, prev_time = previous
        if prev_time < active.start_time:
            return
        step = (timestamp - prev_time).total_seconds()
        if step <= 0 or step > self.MAX_POWER_STEP_SECONDS:
            return
        active.aux_energy_wh = (active.aux_energy_wh or 0.0) + prev_watts * step / 3600.0
        self._heard(vehicle_id, timestamp)

    def _write(self, db: Session, vehicle_id: str, **fields):
        active = self.active.get(vehicle_id)
        if active is None:
            return
        if not crud.update_event(db, active.event_id, **fields):
            self.active.pop(vehicle_id, None)

    @staticmethod
    def _source_label(active: ActiveVehicleEvent) -> str:
        if {'metric', 'event'} <= active.sources:
            return 'both'
        return 'event' if 'event' in active.sources else 'metric'

    def _enabled(self, vehicle_id: str) -> Optional[int]:
        """The vehicle's row id when it records events (the charge-logging switch),
        else None."""
        cached = self._enabled_cache.get(vehicle_id)
        now = time.monotonic()
        if cached is not None and now - cached[2] < self.ENABLED_CACHE_SECONDS:
            return cached[0] if cached[1] else None
        db = SessionLocal()
        try:
            vehicle = vehicle_crud.get_vehicle_by_vehicle_id(db, vehicle_id)
        finally:
            db.close()
        if vehicle is None:
            self._enabled_cache.pop(vehicle_id, None)
            return None
        self._enabled_cache[vehicle_id] = (vehicle.id, bool(vehicle.enable_charge_logging), now)
        return vehicle.id if vehicle.enable_charge_logging else None

    # ---- queries and housekeeping --------------------------------------------------

    def is_event_active(self, event_id: UUID) -> bool:
        with self._lock:
            return any(a.event_id == event_id for a in list(self.active.values()))

    def active_event_ids(self) -> set:
        """The rows being recorded now, in one look — for a page of many rows."""
        return self._held_ids()

    def _held_ids(self) -> set:
        with self._lock:
            return {a.event_id for a in list(self.active.values())}

    def check_for_stale_events(self, db: Session) -> int:
        """End the events whose vehicle went quiet, at the last time it was heard, then
        close the open rows nobody holds; return how many orphans were closed."""
        now = datetime.datetime.now(datetime.timezone.utc)
        with self._lock:
            stale = [
                vid for vid, a in list(self.active.items())
                if (now - as_utc(a.last_activity)).total_seconds() > settings.TIMEOUT_CHARGE_IDLE
            ]
        for vehicle_id in sorted(stale):
            with self._lock:
                active = self.active.get(vehicle_id)
                if active is None:
                    continue
                try:
                    logger.warning(f"Vehicle event of {vehicle_id} is stale; ending it at its last activity.")
                    self._end(db, vehicle_id, active.last_activity)
                except Exception as e:
                    logger.error(f"Could not end stale vehicle event of {vehicle_id}: {e}", exc_info=True)
                    db.rollback()
        return self.close_orphaned_events(db, now=now)

    def close_orphaned_events(self, db: Session, now: Optional[datetime.datetime] = None) -> int:
        now = as_utc(now or datetime.datetime.now(datetime.timezone.utc))
        limit = settings.TIMEOUT_CHARGE_IDLE + self.ORPHAN_CLOCK_MARGIN_SECONDS
        closed = 0
        for event_id in crud.open_event_ids(db):
            with self._lock:
                if event_id in self._held_ids():
                    continue
                try:
                    row = crud.get_event(db, event_id)
                    if row is None or row.end_time is not None:
                        continue
                    last = as_utc(row.last_activity or row.start_time)
                    if (now - last).total_seconds() <= limit:
                        continue
                    if self._close_row_at_last_activity(db, row):
                        closed += 1
                except Exception as e:
                    logger.error(f"Could not close orphaned vehicle event {event_id}: {e}", exc_info=True)
                    db.rollback()
        return closed


event_manager = EventManager()
