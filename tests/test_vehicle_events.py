"""
Climate and 12 V events of a parked vehicle (`app/services/event_logger`).

Pinned here:
- climate while parked is an event; the 12 V coming on during it, before it (by
  minutes, as a parked module's bursts arrive) or running on after it is the *same*
  event, flagged `aux_charged` — never a second one;
- the 12 V alone, parked and not charging, is a boost (`aux_charge`);
- the 12 V still on after a drive is no boost: only a rising edge opens an event;
- driving or an HV charge ends an event; a flicker under a minute leaves nothing;
- the module's `vehicle.charge.12v.start` opens a boost at once, its two topics count
  once, and the metric that follows confirms the event (`source = both`);
- a retained value never opens an event, but resumes an open row after a restart;
- the switch is the vehicle's charge-logging one;
- cabin temperature and setpoint come only from live readings no older than
  `HVAC_READING_MAX_AGE_SECONDS` before the start, else from the first one during the
  event — never the sleeping climate unit's value from the last drive;
- a stale event is ended at its last activity and an orphaned row is closed;
- the list API pages newest first and says `in_progress`; the delete refuses the
  event being recorded (409) and answers 404 with `event_not_found`.
"""

import datetime
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.database import Base
from app.models import db as models_db
from app.services.charge_logger import models as charge_models  # noqa: F401 (registers ChargeLog)
from app.services.event_logger import crud as event_crud
from app.services.event_logger import models as event_models
from app.services.event_logger.event_manager import EventManager

UTC = datetime.timezone.utc
T0 = datetime.datetime(2026, 10, 9, 7, 0, tzinfo=UTC)


def _at(minutes: float) -> datetime.datetime:
    return T0 + datetime.timedelta(minutes=minutes)


@pytest.fixture()
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    owner = models_db.User(username="owner", email="owner@example.invalid",
                           hashed_password="x", is_active=True, is_admin=False)
    session.add(owner)
    session.commit()
    session.add(models_db.Vehicle(vehicle_id="CAR1", owner_id=owner.id, protocol="v3",
                                  encrypted_server_password=b"x", enable_charge_logging=True))
    session.add(models_db.Vehicle(vehicle_id="OFF1", owner_id=owner.id, protocol="v3",
                                  encrypted_server_password=b"x", enable_charge_logging=False))
    session.commit()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


class _Car:
    """The metric store the manager reads, fed like the subscriber feeds it."""

    def __init__(self, manager, vehicle_id="CAR1"):
        self.manager = manager
        self.vehicle_id = vehicle_id
        self.metrics = {"v.e.on": "no", "v.c.charging": "no", "v.b.soc": "60",
                        "v.e.cabintemp": "4", "v.b.12v.voltage": "12.3"}

    def send(self, name, value, at, retained=False):
        self.metrics[name] = value
        self.manager.process_metric(self.vehicle_id, name, value, at, retained=retained)

    def event(self, name, at):
        self.manager.process_event(self.vehicle_id, name, at)


@pytest.fixture()
def manager(db, monkeypatch):
    m = EventManager()
    from app.services.event_logger import event_manager as module
    cars = {}
    monkeypatch.setattr(module, "SessionLocal", lambda: db)
    monkeypatch.setattr(module.metrics_manager, "get_metrics_for_vehicle",
                        lambda vehicle_id: cars[vehicle_id].metrics if vehicle_id in cars else None)
    m._cars = cars
    return m


@pytest.fixture()
def car(manager):
    c = _Car(manager)
    manager._cars["CAR1"] = c
    # The state the module last published, before anything happens.
    for name in ("v.e.hvac", "v.e.charging12v"):
        c.send(name, "no", _at(-60))
    return c


def _events(db):
    db.expire_all()
    return db.query(event_models.VehicleEvent).order_by(event_models.VehicleEvent.start_time).all()


def _utc(value):
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def test_climate_while_parked_is_one_event(db, manager, car):
    car.send("v.e.hvac", "yes", _at(0))
    car.send("v.e.cabintemp", "12", _at(1))
    car.send("v.e.cabintemp", "15", _at(5))
    car.send("v.e.hvac", "no", _at(15))

    [event] = _events(db)
    assert event.kind == "climate"
    assert _utc(event.start_time) == _at(0)
    assert _utc(event.end_time) == _at(15)
    assert event.cabin_temp_start == 12.0 and event.cabin_temp_end == 15.0
    assert event.aux_charged is False
    assert "CAR1" not in manager.active


def test_the_sleeping_climate_units_last_reading_is_not_the_start(db, manager, car):
    # The climate unit sleeps while the car is parked; the last cabin temperature
    # and setpoint it sent are from the end of the drive. Recorded as the start,
    # every preconditioning "cooled" the cabin from 19.5 to the 13.4 it really was.
    car.send("v.e.cabintemp", "19.5", _at(-120))
    car.send("v.e.cabinsetpoint", "0", _at(-120))
    car.send("v.e.hvac", "yes", _at(0))
    [event] = _events(db)
    assert event.cabin_temp_start is None and event.cabin_setpoint is None

    car.send("v.e.cabintemp", "13.4", _at(1))
    car.send("v.e.cabinsetpoint", "22", _at(1))
    car.send("v.e.cabintemp", "16", _at(4))
    car.send("v.e.hvac", "no", _at(5))

    [event] = _events(db)
    assert (event.cabin_temp_start, event.cabin_temp_end, event.cabin_setpoint) == (13.4, 16.0, 22.0)


def test_a_reading_from_just_before_the_start_is_the_start(db, manager, car):
    car.send("v.e.cabintemp", "8", _at(-2))
    car.send("v.e.hvac", "yes", _at(0))
    car.send("v.e.cabintemp", "11", _at(3))
    car.send("v.e.hvac", "no", _at(5))

    [event] = _events(db)
    assert (event.cabin_temp_start, event.cabin_temp_end) == (8.0, 11.0)


def test_a_boost_with_the_climate_unit_asleep_has_no_cabin_temperature(db, manager, car):
    car.send("v.e.cabintemp", "21.3", _at(-300))
    car.send("v.e.charging12v", "yes", _at(0))
    car.send("v.e.charging12v", "no", _at(9))

    [event] = _events(db)
    assert event.cabin_temp_start is None and event.cabin_temp_end is None


def test_a_retained_reading_is_not_fresh(db, manager, car):
    # After a restart the broker replays the unit's last value: its age is unknown.
    car.send("v.e.cabintemp", "19.5", _at(-1), retained=True)
    car.send("v.e.hvac", "yes", _at(0))
    car.send("v.e.hvac", "no", _at(5))

    [event] = _events(db)
    assert event.cabin_temp_start is None and event.cabin_temp_end is None


def test_the_converter_joining_minutes_later_is_the_same_event(db, manager, car):
    car.send("v.e.hvac", "yes", _at(0))
    car.send("v.e.charging12v", "yes", _at(9))
    car.send("v.e.hvac", "no", _at(15))
    # The converter runs on: the tail of the same event, no boost of its own.
    car.send("v.e.charging12v", "no", _at(17))

    [event] = _events(db)
    assert event.kind == "climate"
    assert event.aux_charged is True
    assert _utc(event.end_time) == _at(15)


def test_climate_following_the_converter_turns_the_boost_into_climate(db, manager, car):
    car.send("v.e.charging12v", "yes", _at(0))
    car.send("v.e.hvac", "yes", _at(8))
    car.send("v.e.hvac", "no", _at(20))
    car.send("v.e.charging12v", "no", _at(21))

    [event] = _events(db)
    assert event.kind == "climate"
    assert event.aux_charged is True
    assert _utc(event.start_time) == _at(0), "the event began when the converter did"


def test_the_converter_alone_is_a_boost(db, manager, car):
    car.send("v.e.charging12v", "yes", _at(0))
    car.send("v.c.12v.power", "300", _at(0))
    car.send("v.c.12v.power", "300", _at(10))
    car.send("v.b.12v.voltage", "14.1", _at(19))
    car.send("v.e.charging12v", "no", _at(20))

    [event] = _events(db)
    assert event.kind == "aux_charge"
    assert event.aux_charged is True
    assert event.aux_voltage_start == 12.3 and event.aux_voltage_end == 14.1
    assert event.aux_energy_wh == pytest.approx(50.0)


def test_the_converter_still_on_after_a_drive_is_no_boost(db, manager, car):
    car.send("v.e.on", "yes", _at(0))
    car.send("v.e.charging12v", "yes", _at(1))
    car.send("v.e.on", "no", _at(30))
    car.send("v.e.charging12v", "no", _at(32))
    assert _events(db) == []


def test_driving_and_charging_end_an_event(db, manager, car):
    car.send("v.e.hvac", "yes", _at(0))
    car.send("v.e.on", "yes", _at(10))
    car.send("v.e.on", "no", _at(40))
    car.send("v.e.hvac", "no", _at(41))
    car.send("v.e.charging12v", "yes", _at(50))
    car.send("v.c.charging", "yes", _at(55))

    climate, boost = _events(db)
    assert climate.kind == "climate" and _utc(climate.end_time) == _at(10)
    assert boost.kind == "aux_charge" and _utc(boost.end_time) == _at(55)


def test_a_flicker_leaves_nothing(db, manager, car):
    car.send("v.e.hvac", "yes", _at(0))
    car.send("v.e.hvac", "no", _at(0.5))
    assert _events(db) == []


def test_a_discarded_flicker_does_not_block_the_event_after_it(db, manager, car):
    # 40 s of climate is discarded as a flicker. It set the gap all the same, and
    # the real 30-minute preconditioning starting 20 s later was never recorded.
    car.send("v.e.hvac", "yes", _at(0))
    car.send("v.e.hvac", "no", _at(40 / 60))
    car.send("v.e.hvac", "yes", _at(1))
    car.send("v.e.hvac", "no", _at(31))
    [event] = _events(db)
    assert event.kind == "climate"
    assert _utc(event.start_time) == _at(1) and _utc(event.end_time) == _at(31)


def test_a_pause_shorter_than_the_gap_continues_the_event(db, manager, car):
    # Off and on again within MIN_EVENT_GAP_SECONDS: the edge was used up and the
    # rest of the climate run went unrecorded. It is the same event, reopened.
    car.send("v.e.hvac", "yes", _at(0))
    car.send("v.e.hvac", "no", _at(10))
    car.send("v.e.hvac", "yes", _at(10.25))
    assert "CAR1" in manager.active
    car.send("v.e.hvac", "no", _at(20))
    [event] = _events(db)
    assert _utc(event.start_time) == _at(0) and _utc(event.end_time) == _at(20)
    assert event.kind == "climate"


def test_a_boost_restarting_within_the_gap_continues(db, manager, car):
    car.send("v.e.charging12v", "yes", _at(0))
    car.send("v.e.charging12v", "no", _at(5))
    car.send("v.e.charging12v", "yes", _at(5.2))
    car.send("v.e.charging12v", "no", _at(12))
    [event] = _events(db)
    assert event.kind == "aux_charge"
    assert _utc(event.start_time) == _at(0) and _utc(event.end_time) == _at(12)


def test_after_the_gap_a_rising_edge_is_a_new_event(db, manager, car):
    car.send("v.e.hvac", "yes", _at(0))
    car.send("v.e.hvac", "no", _at(10))
    car.send("v.e.hvac", "yes", _at(11))
    car.send("v.e.hvac", "no", _at(20))
    assert len(_events(db)) == 2


def test_an_event_deleted_in_the_pause_is_not_reopened(db, manager, car):
    car.send("v.e.hvac", "yes", _at(0))
    car.send("v.e.hvac", "no", _at(10))
    [event] = _events(db)
    event_crud.delete_event(db, event.id)
    car.send("v.e.hvac", "yes", _at(10.25))
    assert "CAR1" not in manager.active
    assert _events(db) == []


def test_the_module_event_opens_a_boost_at_once_and_counts_once(db, manager, car):
    car.event("vehicle.charge.12v.start", _at(0))
    # The same event on its second topic, a moment later.
    car.event("vehicle.charge.12v.start", _at(0.01))
    assert len(_events(db)) == 1
    # The metric arrives with the next publish interval and confirms it.
    car.send("v.e.charging12v", "yes", _at(9))
    car.event("vehicle.charge.12v.stop", _at(25))

    [event] = _events(db)
    assert event.kind == "aux_charge"
    assert _utc(event.start_time) == _at(0)
    assert _utc(event.end_time) == _at(25), "the event is the precise end"
    assert event.source == "both"


def test_a_retained_value_opens_nothing_but_resumes_an_open_row(db, manager, car):
    # After a restart the broker replays the last values: no start time to give.
    fresh = EventManager()
    fresh._cars = manager._cars
    manager._cars["CAR1"].manager = fresh
    car.send("v.e.hvac", "yes", _at(0), retained=True)
    assert _events(db) == []

    # An open row from before the restart, active within the idle limit, is resumed.
    vehicle = db.query(models_db.Vehicle).filter_by(vehicle_id="CAR1").one()
    row = event_models.VehicleEvent(vehicle_id_fk=vehicle.id, kind="climate",
                                    start_time=_at(-10), last_activity=_at(-2))
    db.add(row)
    db.commit()
    row_id = row.id
    other = EventManager()
    other._cars = manager._cars
    manager._cars["CAR1"].manager = other
    car.send("v.e.hvac", "yes", _at(0), retained=True)
    assert other.active["CAR1"].event_id == row_id
    car.send("v.e.hvac", "no", _at(5))
    [event] = _events(db)
    assert event.id == row_id and _utc(event.end_time) == _at(5)


def _restarted(manager):
    """A new manager over the same cars and database: the server came back."""
    fresh = EventManager()
    fresh._cars = manager._cars
    for c in manager._cars.values():
        c.manager = fresh
    return fresh


def _open_row(db, kind, start, last):
    vehicle = db.query(models_db.Vehicle).filter_by(vehicle_id="CAR1").one()
    row = event_models.VehicleEvent(vehicle_id_fk=vehicle.id, kind=kind,
                                    start_time=start, last_activity=last)
    db.add(row)
    db.commit()
    return row.id


def test_a_new_climate_after_a_restart_is_not_merged_into_the_old_row(db, manager, car):
    # Climate ran 06:50–07:00; the server went down in the middle and left the row open.
    old_id = _open_row(db, "climate", _at(-10), _at(-5))
    fresh = _restarted(manager)
    # The retained burst says it is off now…
    car.send("v.e.hvac", "no", _at(5), retained=True)
    # …so the preconditioning at 07:20 is a new event, and the old row ends where it
    # was last heard — not resumed across twenty minutes of nothing.
    car.send("v.e.hvac", "yes", _at(20))
    assert fresh.active["CAR1"].event_id != old_id
    car.send("v.e.hvac", "no", _at(30))
    old, new = _events(db)
    assert old.id == old_id and _utc(old.end_time) == _at(-5)
    assert _utc(new.start_time) == _at(20) and _utc(new.end_time) == _at(30)


def test_a_live_value_first_seen_after_a_restart_still_resumes(db, manager, car):
    # Nothing retained said otherwise: the climate still running is the open row's.
    row_id = _open_row(db, "climate", _at(-10), _at(-5))
    fresh = _restarted(manager)
    car.send("v.e.hvac", "yes", _at(2))
    assert fresh.active["CAR1"].event_id == row_id


def test_a_boost_resumed_with_the_heating_on_is_climate_at_once(db, manager, car):
    # A boost ran when the server went down; the heating came on during the
    # downtime. The retained burst resumes the row — and it is climate from there,
    # not only once the next climate metric arrives: a module sends that on a
    # change, and the event ended as a boost with the climate inside it.
    row_id = _open_row(db, "aux_charge", _at(-10), _at(-2))
    fresh = _restarted(manager)
    car.send("v.e.hvac", "yes", _at(1), retained=True)
    assert fresh.active["CAR1"].event_id == row_id
    assert fresh.active["CAR1"].kind == "climate"
    [event] = _events(db)
    assert event.kind == "climate" and event.aux_charged
    car.send("v.e.hvac", "no", _at(8))
    [event] = _events(db)
    assert event.id == row_id and event.kind == "climate" and _utc(event.end_time) == _at(8)


def test_a_retained_end_is_dated_by_the_last_activity(db, manager, car):
    # The car drove off while the server was down: the retained burst ends the
    # resumed event where it was last heard, not at the burst's arrival.
    row_id = _open_row(db, "climate", _at(-10), _at(-2))
    _restarted(manager)
    car.send("v.e.hvac", "yes", _at(25), retained=True)
    car.send("v.e.on", "yes", _at(25), retained=True)
    [event] = _events(db)
    assert event.id == row_id and _utc(event.end_time) == _at(-2)


def test_switching_logging_off_ends_the_running_event(db, manager, car):
    car.send("v.e.hvac", "yes", _at(0))
    car.send("v.e.cabintemp", "10", _at(4))
    vehicle = db.query(models_db.Vehicle).filter_by(vehicle_id="CAR1").one()
    vehicle.enable_charge_logging = False
    db.commit()
    manager._enabled_cache.clear()
    # Any further message ends it at its last activity; it is not kept alive.
    car.send("v.e.cabintemp", "12", _at(8))
    assert "CAR1" not in manager.active
    [event] = _events(db)
    assert _utc(event.end_time) == _at(4)


def test_a_database_error_does_not_use_up_the_edge(db, manager, car, monkeypatch):
    from app.services.event_logger import crud as event_crud

    real = event_crud.create_event
    calls = []

    def failing_once(*a, **k):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("database is locked")
        return real(*a, **k)

    monkeypatch.setattr(event_crud, "create_event", failing_once)
    car.send("v.e.hvac", "yes", _at(0))
    assert _events(db) == []
    # The next message sees the same rising edge again.
    car.send("v.e.heating", "yes", _at(1))
    assert len(_events(db)) == 1


def test_a_charge_older_than_the_metric_cache_is_still_a_charge(db, manager, car):
    car.send("v.c.charging", "yes", _at(0))
    # Hours later the store has dropped the unchanged value.
    del car.metrics["v.c.charging"]
    car.send("v.e.hvac", "yes", _at(300))
    car.send("v.e.hvac", "no", _at(320))
    assert _events(db) == []


def test_the_subscriber_retries_a_refused_event_subscription(monkeypatch):
    from app import mqtt_metrics_subscriber as module

    started = []

    class _Timer:
        def __init__(self, delay, fn, args=()):
            started.append((delay, fn, args))
            self.daemon = False

        def start(self):
            pass

    monkeypatch.setattr(module.threading, "Timer", _Timer)
    sub = module.MqttMetricsSubscriber()

    class _Client:
        def __init__(self):
            self.subscribed = []

        def subscribe(self, topic):
            self.subscribed.append(topic)
            return (0, len(self.subscribed))

        def is_connected(self):
            return True

    client = _Client()
    sub._client = client
    sub._on_connect(client, None, None, 0)
    assert client.subscribed == ["ovms/+/+/metric/#", sub.EVENT_TOPIC]
    # The event topic refused (mid 2): asked again later.
    sub._on_subscribe(client, None, 2, (0x80,))
    assert len(started) == 1
    delay, fn, args = started[0]
    fn(*args)
    assert client.subscribed[-1] == sub.EVENT_TOPIC
    # The retry's SUBACK may be handled before the timer thread has its mid back:
    # a refusal of any mid but the metric one is the event topic's.
    sub._on_subscribe(client, None, 3, (0x80,))
    assert len(started) == 2
    sub._on_subscribe(client, None, 1, (0x80,))
    assert len(started) == 2, "the metric subscription is not the event topic"
    sub._on_subscribe(client, None, 4, (0,))
    assert len(started) == 2


def test_refusals_keep_one_retry_pending_across_reconnects(monkeypatch):
    from app import mqtt_metrics_subscriber as module

    timers = []

    class _Timer:
        def __init__(self, delay, fn, args=()):
            self.fn, self.args, self.cancelled = fn, args, False
            timers.append(self)

        def start(self):
            pass

        def cancel(self):
            self.cancelled = True

    monkeypatch.setattr(module.threading, "Timer", _Timer)
    sub = module.MqttMetricsSubscriber()

    class _Client:
        mids = 0

        def subscribe(self, topic):
            self.mids += 1
            return (0, self.mids)

        def is_connected(self):
            return True

    client = _Client()
    sub._client = client
    sub._on_connect(client, None, None, 0)
    sub._on_subscribe(client, None, 2, (0x80,))
    sub._on_subscribe(client, None, 2, (0x80,))
    assert len(timers) == 1, "a second refusal does not start a second chain"
    # A reconnect: the pending retry is cancelled, the new connection asks afresh.
    sub._on_disconnect(client, None, 1)
    assert timers[0].cancelled
    sub._on_connect(client, None, None, 0)
    sub._on_subscribe(client, None, client.mids, (0x80,))
    assert len(timers) == 2
    live = [t for t in timers if not t.cancelled]
    assert len(live) == 1
    live[0].fn(*live[0].args)
    sub._on_subscribe(client, None, client.mids, (0x80,))
    assert len([t for t in timers if not t.cancelled]) == 2 and len(timers) == 3


def test_a_climate_longer_than_the_metric_store_keeps_is_not_cut_short(db, manager, car):
    car.send("v.e.hvac", "yes", _at(0))
    # Hours later the store has dropped the unchanged value.
    del car.metrics["v.e.hvac"]
    car.send("v.e.charging12v", "yes", _at(200))
    assert "CAR1" in manager.active
    car.send("v.e.hvac", "no", _at(240))
    [event] = _events(db)
    assert _utc(event.end_time) == _at(240)


def test_a_vehicle_without_charge_logging_records_nothing(db, manager):
    off = _Car(manager, "OFF1")
    manager._cars["OFF1"] = off
    off.send("v.e.hvac", "no", _at(-1))
    off.send("v.e.hvac", "yes", _at(0))
    off.send("v.e.hvac", "no", _at(10))
    assert _events(db) == []


def test_a_stale_event_ends_at_its_last_activity_and_orphans_are_closed(db, manager, car):
    start = datetime.datetime.now(UTC) - datetime.timedelta(hours=3)
    car.send("v.e.hvac", "yes", start)
    car.send("v.e.cabintemp", "12", start + datetime.timedelta(minutes=10))
    vehicle = db.query(models_db.Vehicle).filter_by(vehicle_id="CAR1").one()
    orphan = event_models.VehicleEvent(
        vehicle_id_fk=vehicle.id, kind="aux_charge",
        start_time=start - datetime.timedelta(hours=5),
        last_activity=start - datetime.timedelta(hours=4))
    db.add(orphan)
    db.commit()
    orphan_id = orphan.id

    assert manager.check_for_stale_events(db) == 1
    events = {e.id: e for e in _events(db)}
    assert _utc(events[orphan_id].end_time) == start - datetime.timedelta(hours=4)
    held = [e for e in events.values() if e.kind == "climate"][0]
    assert _utc(held.end_time) == start + datetime.timedelta(minutes=10)
    assert "CAR1" not in manager.active


def test_the_api_pages_reports_in_progress_and_guards_the_delete(db, manager, car, monkeypatch):
    from fastapi import HTTPException

    from app.services.charge_logger import api as charge_api

    monkeypatch.setattr(charge_api, "event_manager", manager)
    monkeypatch.setattr(charge_api.crud, "check_vehicle_ownership", lambda *a, **k: True)

    car.send("v.e.hvac", "yes", _at(0))
    car.send("v.e.hvac", "no", _at(10))
    car.send("v.e.charging12v", "yes", _at(30))
    finished, running = _events(db)
    user = SimpleNamespace(id=1)

    page = charge_api.get_vehicle_events("car1", page=1, limit=1, db=db, current_user=user)
    assert page.pagination.total_items == 2 and page.pagination.total_pages == 2
    assert [e.id for e in page.events] == [running.id], "newest start first"
    assert page.events[0].in_progress is True
    second = charge_api.get_vehicle_events("CAR1", page=2, limit=1, db=db, current_user=user)
    assert second.events[0].id == finished.id
    assert second.events[0].duration_seconds == 600
    assert second.events[0].in_progress is False

    with pytest.raises(HTTPException) as refused:
        charge_api.delete_vehicle_event(running.id, db=db, current_user=user)
    assert refused.value.status_code == 409

    assert charge_api.delete_vehicle_event(finished.id, db=db, current_user=user).status_code == 204
    with pytest.raises(HTTPException) as gone:
        charge_api.delete_vehicle_event(finished.id, db=db, current_user=user)
    assert gone.value.status_code == 404
    assert gone.value.detail == "event_not_found"


def test_the_subscriber_reads_both_event_topics(monkeypatch):
    from app import mqtt_metrics_subscriber as module

    seen = []
    monkeypatch.setattr(module.event_manager, "process_event",
                        lambda vid, name, ts: seen.append((vid, name)))
    monkeypatch.setattr(module.mqtt_topic_auth, "topic_owner_matches", lambda *a: True)
    sub = module.MqttMetricsSubscriber()
    legacy = SimpleNamespace(topic="ovms/user/car1/event", payload=b"vehicle.charge.12v.start", retain=False)
    styled = SimpleNamespace(topic="ovms/user/car1/event/vehicle/charge/12v/stop", payload=b"", retain=False)
    ignored = SimpleNamespace(topic="ovms/user/car1/event/ticker/60", payload=b"", retain=False)
    for msg in (legacy, styled, ignored):
        sub._on_message(None, None, msg)
    assert seen == [("CAR1", "vehicle.charge.12v.start"), ("CAR1", "vehicle.charge.12v.stop")]


def test_the_idle_limit_is_the_charge_log_one():
    # One knob for "a parked module is quiet for this long": both loggers end on it.
    assert settings.TIMEOUT_CHARGE_IDLE >= 1200
