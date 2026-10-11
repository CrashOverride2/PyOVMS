"""
Charge sessions left open by a restart are closed — or resumed — never left open.

A charge row is written with `end_time` NULL and closed only by the in-memory
`ChargeManager`. A restart mid-charge therefore lost the session while the row stayed
open, nothing ever closed it, and the vehicle page showed it as a charge "in progress"
for good. And because the module's retained `v.c.charging=yes` comes again on
reconnect, the charge itself was split: a second row opened mid-charge beside the
orphan.

Pinned here:
- the stale check closes an open row nobody holds once its last point is older than
  `TIMEOUT_CHARGE_IDLE` plus the vehicle-clock margin, at that point, with its SOC and
  the power figures;
- a younger one is left alone (it may be resumed), and so is a row a session holds —
  also one resumed between the pass reading the open rows and writing one;
- a session that comes back within that window resumes the open row; from the
  retained burst it moves no clock and writes no point, and if the module is never
  heard live it is closed at its last point like any orphan;
- an orphan with no points, or a flapping one, is discarded; one cut off after its
  start point is kept;
- one row failing does not keep the others open, and the writes are conditional on
  the row still being open;
- a point whose row is gone is reported, not swallowed as a duplicate, and the session
  is dropped;
- the state is read and written under the manager's lock;
- the first housekeeping pass runs minutes after startup, not an hour;
- the list API says `in_progress` only for a row that is being recorded, and the delete
  refuses that row (409) while an orphan or a closed one goes.
"""

import asyncio
import datetime
import threading
import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.database import Base
from app.models import db as models_db
from app.services.charge_logger import crud as charge_crud
from app.services.charge_logger import models as charge_models
from app.services.charge_logger.charge_manager import ActiveChargeSession, ChargeManager

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 10, 2, 12, 0, tzinfo=UTC)
IDLE = datetime.timedelta(seconds=settings.TIMEOUT_CHARGE_IDLE)
MARGIN = datetime.timedelta(seconds=ChargeManager.ORPHAN_CLOCK_MARGIN_SECONDS)
# Past the point where an orphan is closed: the idle limit plus the clock margin.
CLOSABLE = IDLE + MARGIN


def _make_db(foreign_keys=False):
    # One connection for every thread: an in-memory database is per connection, and
    # the lock tests call in from a second thread.
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    if foreign_keys:
        # The production SQLite runs without it; PostgreSQL and MySQL enforce the key.
        @event.listens_for(engine, "connect")
        def _fk_on(dbapi_connection, record):  # noqa: ARG001
            dbapi_connection.execute("PRAGMA foreign_keys=ON")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    owner = models_db.User(
        username="owner", email="owner@example.invalid",
        hashed_password="x", is_active=True, is_admin=False,
    )
    session.add(owner)
    session.commit()
    for vehicle_id in ("CAR1", "CAR2"):
        session.add(models_db.Vehicle(
            vehicle_id=vehicle_id, owner_id=owner.id, protocol="v3",
            encrypted_server_password=b"x", enable_charge_logging=True,
        ))
    session.commit()
    return engine, session


@pytest.fixture()
def db():
    engine, session = _make_db()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture()
def fk_db():
    engine, session = _make_db(foreign_keys=True)
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


@pytest.fixture()
def manager(db, monkeypatch):
    m = ChargeManager()
    from app.services.charge_logger import charge_manager as module
    # process_metric opens its own session; hand it the test database.
    monkeypatch.setattr(module, "SessionLocal", lambda: db)
    # The metrics cache is a process-wide singleton; a session's points read it.
    monkeypatch.setattr(module.metrics_manager, "get_metrics_for_vehicle",
                        lambda vehicle_id: {"v.b.soc": "55", "v.c.power": "7.2"})
    return m


def _vehicle(db, vehicle_id="CAR1"):
    return db.query(models_db.Vehicle).filter_by(vehicle_id=vehicle_id).one()


def _open_row(db, start, points=(), vehicle_id="CAR1"):
    log = charge_models.ChargeLog(vehicle_id_fk=_vehicle(db, vehicle_id).id, start_time=start, start_soc=20.0)
    db.add(log)
    db.commit()
    for ts, soc, power in points:
        db.add(charge_models.ChargeLogPoint(charge_log_id_fk=log.id, timestamp=ts, soc=soc, power_kw=power))
    db.commit()
    return log.id


def _row(db, log_id):
    db.expire_all()
    return db.query(charge_models.ChargeLog).filter_by(id=log_id).one_or_none()


def _utc(value):
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _point_count(db, log_id):
    db.expire_all()
    return db.query(charge_models.ChargeLogPoint).filter_by(charge_log_id_fk=log_id).count()


def test_an_orphan_past_the_idle_limit_is_closed_at_its_last_point(db, manager):
    last = NOW - CLOSABLE - datetime.timedelta(minutes=5)
    log_id = _open_row(db, last - datetime.timedelta(hours=2), points=[
        (last - datetime.timedelta(hours=2), 20.0, 11.0),
        (last - datetime.timedelta(hours=1), 50.0, 9.0),
        (last, 80.0, 4.0),
    ])

    assert manager.close_orphaned_sessions(db, now=NOW) == 1

    row = _row(db, log_id)
    assert _utc(row.end_time) == last
    assert row.end_soc == 80.0
    assert row.energy_added_kwh is None, "v.c.kwh was only in memory; it must not be guessed"
    assert row.max_power_kw == 11.0
    assert row.average_power_kw == pytest.approx(8.0)


def test_an_orphan_without_points_ends_at_its_start_and_is_discarded(db, manager):
    """No points means no duration: shorter than a charge, so removed like a live one."""
    log_id = _open_row(db, NOW - CLOSABLE - datetime.timedelta(hours=1))

    assert manager.close_orphaned_sessions(db, now=NOW) == 1
    assert _row(db, log_id) is None


def test_an_orphan_with_only_its_start_point_is_discarded(db, manager):
    """One reading has no duration and says nothing about where the charge got to —
    not a charge log, so it goes like a row without points, points included."""
    start = NOW - CLOSABLE - datetime.timedelta(hours=1)
    log_id = _open_row(db, start, points=[(start, 20.0, 7.0)])

    assert manager.close_orphaned_sessions(db, now=NOW) == 1
    assert _row(db, log_id) is None
    assert _point_count(db, log_id) == 0


def test_a_flapping_orphan_with_several_points_is_discarded(db, manager):
    """Two readings within a minute of the start and nothing after is what a flapping
    `v.c.charging` leaves — removed, as on a live end."""
    start = NOW - CLOSABLE - datetime.timedelta(hours=1)
    log_id = _open_row(db, start, points=[
        (start, 20.0, 7.0), (start + datetime.timedelta(seconds=20), 20.0, 7.0),
    ])

    assert manager.close_orphaned_sessions(db, now=NOW) == 1
    assert _row(db, log_id) is None
    assert _point_count(db, log_id) == 0, "SQLite does not cascade; the points go explicitly"


def test_the_close_waits_out_the_vehicle_clock_margin(db, manager):
    """A resume measures on the message clock — server time plus the vehicle's offset,
    up to MAX_VEHICLE_CLOCK_SKEW_SECONDS either way — and the close on server time. A
    row past the idle limit but inside the margin may still be resumed by a vehicle
    whose clock runs behind, so it is left open."""
    last = NOW - IDLE - MARGIN + datetime.timedelta(seconds=10)
    log_id = _open_row(db, last - datetime.timedelta(hours=1), points=[
        (last - datetime.timedelta(hours=1), 20.0, 7.0), (last, 60.0, 7.0),
    ])

    assert manager.close_orphaned_sessions(db, now=NOW) == 0
    assert _row(db, log_id).end_time is None

    # A vehicle clock 290 s behind still dates its message inside the idle limit.
    manager.process_metric("CAR1", "v.c.charging", "yes", NOW - datetime.timedelta(seconds=290))
    assert manager.active_sessions["CAR1"].charge_log_id == log_id


def test_the_clock_margin_matches_the_subscriber_skew_limit():
    from app.mqtt_metrics_subscriber import MqttMetricsSubscriber

    assert ChargeManager.ORPHAN_CLOCK_MARGIN_SECONDS == MqttMetricsSubscriber.MAX_VEHICLE_CLOCK_SKEW_SECONDS


def test_a_recent_orphan_is_left_open(db, manager):
    """Inside the idle limit the vehicle may still report charging and resume it — and
    it is the limit after which a held session counts as stale, too."""
    last = NOW - IDLE + datetime.timedelta(minutes=1)
    log_id = _open_row(db, last - datetime.timedelta(hours=1), points=[(last, 60.0, 7.0)])

    assert manager.close_orphaned_sessions(db, now=NOW) == 0
    assert _row(db, log_id).end_time is None


def test_a_row_a_session_holds_is_never_touched(db, manager):
    start = NOW - CLOSABLE - datetime.timedelta(hours=3)
    manager.process_metric("CAR1", "v.c.charging", "yes", start)
    held_id = next(iter(manager.active_sessions.values())).charge_log_id
    # Fresh in memory, although its last point is old: it is recording.
    manager.active_sessions["CAR1"] = manager.active_sessions["CAR1"]._replace(last_metric_time=NOW)

    assert manager.close_orphaned_sessions(db, now=NOW) == 0
    assert _row(db, held_id).end_time is None
    assert manager.is_session_active(held_id)


def test_a_row_resumed_while_the_pass_runs_is_not_closed(db, manager, monkeypatch):
    """The pass reads the open rows, then decides each one. A resume landing in between
    used to be followed by the close — or the delete — of the row it had just taken
    over, and every later point of that live session then failed its foreign key. The
    held set is read again under the lock, per row, right before the write."""
    start = NOW - CLOSABLE - datetime.timedelta(hours=1)
    log_id = _open_row(db, start, points=[(start, 20.0, 7.0), (start + datetime.timedelta(minutes=30), 50.0, 7.0)])

    def resume():
        manager.active_sessions["CAR1"] = ActiveChargeSession(
            charge_log_id=log_id, vehicle_id="CAR1", vehicle_db_id=_vehicle(db).id,
            start_time=start, last_metric_time=NOW, last_point_save_time=NOW, last_known_kwh=None,
        )

    real_query = db.query
    fired = []

    class _ResumeAfterRead:
        """The pass's read of the open rows, with a resume landing right after it."""
        def __init__(self, query):
            self._query = query

        def filter(self, *a, **k):
            return _ResumeAfterRead(self._query.filter(*a, **k))

        def order_by(self, *a, **k):
            return _ResumeAfterRead(self._query.order_by(*a, **k))

        def all(self):
            rows = self._query.all()
            fired.append(True)
            resume()
            return rows

    def query(*entities, **kwargs):
        q = real_query(*entities, **kwargs)
        if not fired and entities == (charge_models.ChargeLog.id,):
            return _ResumeAfterRead(q)
        return q

    monkeypatch.setattr(db, "query", query)

    assert manager.close_orphaned_sessions(db, now=NOW) == 0
    assert fired
    assert _row(db, log_id).end_time is None


def test_the_writes_only_touch_a_row_that_is_still_open(db):
    """The last line of defence against anything closing the row in between."""
    start = NOW - datetime.timedelta(hours=2)
    log_id = _open_row(db, start, points=[(start, 20.0, 7.0)])
    charge_crud.update_charge_log(db, log_id, end_time=start + datetime.timedelta(hours=1), end_soc=80.0, energy_added_kwh=30.0)

    assert charge_crud.close_open_charge_log(db, log_id, end_time=start, end_soc=None, energy_added_kwh=None) is False
    assert charge_crud.delete_open_charge_log(db, log_id) is False

    row = _row(db, log_id)
    assert _utc(row.end_time) == start + datetime.timedelta(hours=1)
    assert row.end_soc == 80.0 and row.energy_added_kwh == 30.0
    assert _point_count(db, log_id) == 1


def test_one_failing_orphan_does_not_keep_the_others_open(db, manager, monkeypatch):
    """No per-row try used to mean the first row that raised ended the pass, on every
    pass, for every row after it. They are taken in start order."""
    older_start = NOW - CLOSABLE - datetime.timedelta(hours=5)
    newer_start = NOW - CLOSABLE - datetime.timedelta(hours=2)
    # Created newest first, so only the ORDER BY puts the older one first.
    newer_id = _open_row(db, newer_start, points=[
        (newer_start, 20.0, 7.0), (newer_start + datetime.timedelta(hours=1), 60.0, 7.0),
    ], vehicle_id="CAR2")
    older_id = _open_row(db, older_start, points=[
        (older_start, 20.0, 7.0), (older_start + datetime.timedelta(hours=1), 60.0, 7.0),
    ])

    real_close = charge_crud.close_open_charge_log
    seen = []

    def flaky_close(db_, charge_log_id, **kwargs):
        seen.append(charge_log_id)
        if charge_log_id == older_id:
            raise RuntimeError("database is locked")
        return real_close(db_, charge_log_id=charge_log_id, **kwargs)

    monkeypatch.setattr(charge_crud, "close_open_charge_log", flaky_close)

    assert manager.close_orphaned_sessions(db, now=NOW) == 1
    assert seen == [older_id, newer_id]
    assert _row(db, older_id).end_time is None
    assert _row(db, newer_id).end_time is not None


def test_one_failing_stale_session_does_not_keep_the_others(db, manager, monkeypatch):
    long_ago = datetime.datetime.now(UTC) - IDLE - datetime.timedelta(hours=2)
    manager.process_metric("CAR1", "v.c.charging", "yes", long_ago)
    manager.process_metric("CAR2", "v.c.charging", "yes", long_ago)
    car2_id = manager.active_sessions["CAR2"].charge_log_id
    for vid in ("CAR1", "CAR2"):
        s = manager.active_sessions[vid]
        manager.active_sessions[vid] = s._replace(last_metric_time=long_ago + datetime.timedelta(hours=1))

    real_update = charge_crud.update_charge_log

    def flaky_update(db_, charge_log_id, **kwargs):
        if charge_log_id != car2_id:
            raise RuntimeError("database is locked")
        return real_update(db_, charge_log_id=charge_log_id, **kwargs)

    monkeypatch.setattr(charge_crud, "update_charge_log", flaky_update)

    manager.check_for_stale_sessions(db)  # must not raise

    assert manager.active_sessions == {}
    assert _utc(_row(db, car2_id).end_time) == long_ago + datetime.timedelta(hours=1)


def test_the_hourly_stale_check_closes_orphans(db, manager):
    last = datetime.datetime.now(UTC) - CLOSABLE - datetime.timedelta(minutes=10)
    log_id = _open_row(db, last - datetime.timedelta(hours=1), points=[
        (last - datetime.timedelta(hours=1), 30.0, 7.0), (last, 70.0, 7.0),
    ])

    assert manager.check_for_stale_sessions(db) == 1
    assert _row(db, log_id).end_time is not None


def test_charging_again_within_the_idle_limit_resumes_the_open_row(db, manager):
    """A restart mid-charge: the retained `v.c.charging=yes` must not open a second row."""
    start = NOW - datetime.timedelta(hours=1)
    last = NOW - datetime.timedelta(minutes=4)
    log_id = _open_row(db, start, points=[(start, 20.0, 7.0), (last, 45.0, 7.0)])

    manager.process_metric("CAR1", "v.c.charging", "yes", NOW)

    assert db.query(charge_models.ChargeLog).count() == 1
    session = manager.active_sessions["CAR1"]
    assert session.charge_log_id == log_id
    assert session.start_time == start

    manager.process_metric("CAR1", "v.c.charging", "no", NOW + datetime.timedelta(minutes=30))
    row = _row(db, log_id)
    assert _utc(row.end_time) == NOW + datetime.timedelta(minutes=30)
    assert row.end_soc == 55.0


def test_a_resume_from_retained_values_moves_no_clock(db, manager):
    """After a restart the whole retained burst arrives at once, stamped with its
    arrival. A module that went offline mid-charge was resumed from it, a point was
    written at restart time and the session was later ended there — the charge
    stretched over the downtime. Resumed from retained values, the session stays at the
    row's last point and writes nothing; never heard live, it is closed there as the
    orphan it is."""
    real_now = datetime.datetime.now(UTC)
    last = real_now - IDLE - datetime.timedelta(minutes=1)
    start = last - datetime.timedelta(hours=1)
    log_id = _open_row(db, start, points=[(start, 20.0, 7.0), (last, 45.0, 7.0)])

    burst = last + datetime.timedelta(minutes=10)  # the restart, inside the idle limit
    for name, value in (("v.c.charging", "yes"), ("v.b.soc", "60"), ("v.c.power", "7.2"), ("v.b.temp", "25")):
        manager.process_metric("CAR1", name, value, burst, retained=True)

    session = manager.active_sessions["CAR1"]
    assert session.charge_log_id == log_id
    assert session.heard_live is False
    assert _utc(session.last_metric_time) == last
    assert _point_count(db, log_id) == 2

    assert manager.check_for_stale_sessions(db) == 1

    assert "CAR1" not in manager.active_sessions
    row = _row(db, log_id)
    assert _utc(row.end_time) == last, "ended where its record ends, not at the restart"
    assert row.end_soc == 45.0
    assert row.energy_added_kwh is None
    assert _point_count(db, log_id) == 2


def test_a_resumed_session_heard_live_carries_on_as_a_live_one(db, manager):
    start = NOW - datetime.timedelta(hours=1)
    last = NOW - datetime.timedelta(minutes=10)
    log_id = _open_row(db, start, points=[(start, 20.0, 7.0), (last, 45.0, 7.0)])

    manager.process_metric("CAR1", "v.c.charging", "yes", NOW, retained=True)
    manager.process_metric("CAR1", "v.b.soc", "50", NOW + datetime.timedelta(minutes=1))

    session = manager.active_sessions["CAR1"]
    assert session.heard_live is True
    assert _utc(session.last_metric_time) == NOW + datetime.timedelta(minutes=1)

    manager.process_metric("CAR1", "v.c.charging", "no", NOW + datetime.timedelta(minutes=20))
    assert _utc(_row(db, log_id).end_time) == NOW + datetime.timedelta(minutes=20)


def test_retained_values_write_no_point_into_a_live_session(db, manager):
    manager.process_metric("CAR1", "v.c.charging", "yes", NOW)
    log_id = manager.active_sessions["CAR1"].charge_log_id
    assert _point_count(db, log_id) == 1

    manager.process_metric("CAR1", "v.b.soc", "70", NOW + datetime.timedelta(minutes=10), retained=True)

    assert _utc(manager.active_sessions["CAR1"].last_metric_time) == NOW
    assert _point_count(db, log_id) == 1


def test_a_new_charge_after_a_restart_is_not_merged_into_the_old_row(db, manager):
    """A restart mid-charge left the row open; the retained burst then said the
    vehicle is not charging. The next start is a new charge: the old row ends at its
    last point, it is not resumed with the pause inside it."""
    start = NOW - datetime.timedelta(minutes=40)
    last = NOW - datetime.timedelta(minutes=20)
    old_id = _open_row(db, start, points=[(start, 20.0, 7.0), (last, 45.0, 7.0)])

    manager.process_metric("CAR1", "v.c.charging", "no", NOW - datetime.timedelta(minutes=10), retained=True)
    manager.process_metric("CAR1", "v.c.charging", "yes", NOW)

    new_id = manager.active_sessions["CAR1"].charge_log_id
    assert new_id != old_id
    old = _row(db, old_id)
    assert _utc(old.end_time) == last and old.end_soc == 45.0


def test_a_live_start_first_heard_after_a_restart_still_resumes(db, manager):
    start = NOW - datetime.timedelta(minutes=40)
    last = NOW - datetime.timedelta(minutes=5)
    log_id = _open_row(db, start, points=[(start, 20.0, 7.0), (last, 45.0, 7.0)])
    manager.process_metric("CAR1", "v.c.charging", "yes", NOW)
    assert manager.active_sessions["CAR1"].charge_log_id == log_id


def test_a_retained_end_is_dated_by_the_last_activity(db, manager):
    """The broker link dropped mid-charge and the charge ended meanwhile: the retained
    "no" on reconnect ends the session where it was last heard, not at the reconnect."""
    manager.process_metric("CAR1", "v.c.charging", "yes", NOW)
    log_id = manager.active_sessions["CAR1"].charge_log_id
    heard = NOW + datetime.timedelta(minutes=10)
    manager.process_metric("CAR1", "v.b.soc", "60", heard)
    manager.process_metric("CAR1", "v.c.charging", "no", NOW + datetime.timedelta(minutes=45), retained=True)
    assert "CAR1" not in manager.active_sessions
    assert _utc(_row(db, log_id).end_time) == heard


def test_a_retained_start_after_the_end_was_heard_is_a_new_charge(db, manager):
    """The end was heard; the broker link then dropped and the car started again. The
    retained "yes" on reconnect is a new charge, not the old row resumed."""
    start = NOW - datetime.timedelta(minutes=40)
    last = NOW - datetime.timedelta(minutes=20)
    old_id = _open_row(db, start, points=[(start, 20.0, 7.0), (last, 45.0, 7.0)])
    manager.process_metric("CAR1", "v.c.charging", "no", NOW - datetime.timedelta(minutes=10))
    # Heard not charging with nothing held: the left-open row is closed at once.
    assert _utc(_row(db, old_id).end_time) == last
    manager.process_metric("CAR1", "v.c.charging", "yes", NOW, retained=True)
    assert manager.active_sessions["CAR1"].charge_log_id != old_id


def test_a_failing_close_does_not_lose_the_new_charge(db, manager, monkeypatch):
    start = NOW - datetime.timedelta(minutes=40)
    _open_row(db, start, points=[(start, 20.0, 7.0)])
    manager._seen_charging["CAR1"] = False

    def broken(*a, **k):
        raise RuntimeError("database is locked")

    monkeypatch.setattr(manager, "_close_open_row", broken)
    manager.process_metric("CAR1", "v.c.charging", "yes", NOW)
    assert "CAR1" in manager.active_sessions


def test_a_retained_end_keeps_a_charge_the_energy_proves(db, manager, monkeypatch):
    """Never heard again after its start, the session would be under the minimum at
    its last activity and deleted; the retained v.c.kwh says a charge happened."""
    from app.services.charge_logger import charge_manager as module
    monkeypatch.setattr(module.metrics_manager, "get_metrics_for_vehicle",
                        lambda vehicle_id: {"v.b.soc": "70", "v.c.kwh": "12.5"})
    manager.process_metric("CAR1", "v.c.charging", "yes", NOW)
    log_id = manager.active_sessions["CAR1"].charge_log_id
    reconnect = NOW + datetime.timedelta(minutes=25)
    manager.process_metric("CAR1", "v.c.kwh", "12.5", reconnect, retained=True)
    manager.process_metric("CAR1", "v.c.charging", "no", reconnect, retained=True)
    row = _row(db, log_id)
    assert row is not None and row.energy_added_kwh == 12.5
    assert _utc(row.end_time) == reconnect


def test_the_subscriber_passes_the_retained_flag_on(monkeypatch):
    from app import mqtt_metrics_subscriber as sub_module

    calls = []
    monkeypatch.setattr(sub_module.mqtt_topic_auth, "topic_owner_matches", lambda *a, **k: True)
    monkeypatch.setattr(sub_module.metrics_manager, "update_metric", lambda *a, **k: True)
    monkeypatch.setattr(sub_module.charge_manager, "process_metric",
                        lambda *a, **k: calls.append(k.get("retained")))

    subscriber = sub_module.MqttMetricsSubscriber()
    msg = SimpleNamespace(topic="ovms/owner/CAR1/metric/v/c/charging", payload=b"yes", retain=True)
    subscriber._on_message(None, None, msg)

    assert calls == [True]


def test_a_point_for_a_row_that_is_gone_is_reported(db):
    """Every IntegrityError used to be read as the expected duplicate and swallowed —
    the foreign-key violation of a deleted row included, so a whole charge's points were
    dropped without a word. On SQLite, which does not enforce the key here, the point
    went in beside nothing."""
    gone = uuid.uuid4()
    assert charge_crud.create_charge_log_point(db, gone, NOW, soc=50, power_kw=7, battery_temp_c=20) is False
    assert db.query(charge_models.ChargeLogPoint).count() == 0


def test_a_duplicate_point_is_still_ignored(db):
    log_id = _open_row(db, NOW, points=[(NOW, 20.0, 7.0)])
    assert charge_crud.create_charge_log_point(db, log_id, NOW, soc=21, power_kw=7, battery_temp_c=20) is True
    assert _point_count(db, log_id) == 1


def test_a_foreign_key_violation_is_not_taken_for_a_duplicate(fk_db, monkeypatch):
    """The row deleted between the check and the insert: the enforced foreign key
    raises, and it is told apart from the duplicate by looking, on every backend."""
    db = fk_db
    log_id = _open_row(db, NOW)
    real_exists = charge_crud._charge_log_exists
    checks = []

    def exists_then_deleted(db_, charge_log_id):
        checks.append(charge_log_id)
        if len(checks) == 1:
            result = real_exists(db_, charge_log_id)
            charge_crud.delete_charge_log(db_, charge_log_id)
            return result
        return real_exists(db_, charge_log_id)

    monkeypatch.setattr(charge_crud, "_charge_log_exists", exists_then_deleted)

    assert charge_crud.create_charge_log_point(db, log_id, NOW, soc=50, power_kw=7, battery_temp_c=20) is False
    assert len(checks) == 2


def test_any_other_integrity_error_is_raised(db):
    log_id = _open_row(db, NOW)
    with pytest.raises(IntegrityError):
        charge_crud.create_charge_log_point(db, log_id, None, soc=50, power_kw=7, battery_temp_c=20)


def test_a_session_whose_row_was_deleted_is_dropped(db, manager):
    manager.process_metric("CAR1", "v.c.charging", "yes", NOW)
    log_id = manager.active_sessions["CAR1"].charge_log_id
    charge_crud.delete_charge_log(db, log_id)

    manager.process_metric("CAR1", "v.b.soc", "60", NOW + datetime.timedelta(minutes=6))

    assert "CAR1" not in manager.active_sessions
    assert db.query(charge_models.ChargeLogPoint).count() == 0


@pytest.mark.parametrize("call", [
    lambda m, db: m.is_session_active(uuid.uuid4()),
    lambda m, db: m.process_metric("CAR1", "v.c.charging", "yes", NOW),
    lambda m, db: m.check_for_stale_sessions(db),
], ids=["is_session_active", "process_metric", "check_for_stale_sessions"])
def test_the_session_state_is_only_touched_under_the_lock(db, manager, call):
    """paho's network thread, the event loop (V2), the housekeeping pass and the API
    all reach the same dict. Iterated while another thread changed it, it raised."""
    held = threading.Event()
    release = threading.Event()
    done = threading.Event()

    def holder():
        with manager._lock:
            held.set()
            release.wait(5)

    def caller():
        call(manager, db)
        done.set()

    t1 = threading.Thread(target=holder)
    t1.start()
    assert held.wait(5)
    t2 = threading.Thread(target=caller)
    t2.start()
    try:
        assert not done.wait(0.2), "ran without waiting for the lock"
    finally:
        release.set()
        t1.join(5)
        t2.join(5)
    assert done.is_set()


def test_the_first_housekeeping_pass_runs_minutes_after_start(monkeypatch):
    """It used to wait a full hour, so orphans stayed open for up to an hour and a half
    after a restart — and for good on a server restarted more often than hourly."""
    from app import lifespan

    slept = []
    passes = []
    shutdown = []

    async def fake_sleep(seconds):
        slept.append(seconds)

    async def fake_threadpool(fn, db):
        passes.append(len(slept))
        if len(passes) == 2:
            shutdown[0].set()

    monkeypatch.setattr(lifespan, "asyncio", SimpleNamespace(sleep=fake_sleep, CancelledError=asyncio.CancelledError))
    monkeypatch.setattr(lifespan, "run_in_threadpool", fake_threadpool)
    monkeypatch.setattr(lifespan, "SessionLocal", lambda: SimpleNamespace(close=lambda: None))
    monkeypatch.setattr(lifespan.metrics_manager, "evict_stale_metrics", lambda: None)
    monkeypatch.setattr(lifespan.security_manager, "sweep_stale_username_entries", lambda: None)

    async def run():
        shutdown.append(asyncio.Event())
        await lifespan.periodic_housekeeping(shutdown[0])

    asyncio.run(run())

    first = lifespan.HOUSEKEEPING_FIRST_DELAY_SECONDS
    assert first <= 600
    assert passes == [first, first + lifespan.HOUSEKEEPING_INTERVAL_SECONDS]


def test_charging_long_after_an_orphan_opens_a_new_row(db, manager):
    last = NOW - IDLE - datetime.timedelta(minutes=1)
    old_id = _open_row(db, last - datetime.timedelta(hours=1), points=[(last, 50.0, 7.0)])

    manager.process_metric("CAR1", "v.c.charging", "yes", NOW)

    assert manager.active_sessions["CAR1"].charge_log_id != old_id
    assert db.query(charge_models.ChargeLog).count() == 2


def test_the_list_api_reports_in_progress_only_for_a_recorded_session(db, manager, monkeypatch):
    from app.services.charge_logger import api as charge_api

    monkeypatch.setattr(charge_api, "charge_manager", manager)
    monkeypatch.setattr(charge_api.crud, "check_vehicle_ownership", lambda *a, **k: True)

    orphan_id = _open_row(db, datetime.datetime.now(UTC) - datetime.timedelta(hours=5))
    manager.process_metric("CAR1", "v.c.charging", "yes", datetime.datetime.now(UTC))
    live_id = manager.active_sessions["CAR1"].charge_log_id
    assert live_id != orphan_id

    result = charge_api.get_charge_logs_for_vehicle(
        "CAR1", page=1, limit=10, db=db, current_user=SimpleNamespace(id=1),
    )
    flags = {c.id: c.in_progress for c in result.charges}
    assert flags == {live_id: True, orphan_id: False}


def test_the_delete_refuses_a_session_being_recorded(db, manager, monkeypatch):
    from fastapi import HTTPException

    from app.services.charge_logger import api as charge_api

    monkeypatch.setattr(charge_api, "charge_manager", manager)
    monkeypatch.setattr(charge_api.crud, "check_vehicle_ownership", lambda *a, **k: True)

    orphan_id = _open_row(db, datetime.datetime.now(UTC) - datetime.timedelta(hours=5))
    manager.process_metric("CAR1", "v.c.charging", "yes", datetime.datetime.now(UTC))
    live_id = manager.active_sessions["CAR1"].charge_log_id
    user = SimpleNamespace(id=1)

    with pytest.raises(HTTPException) as refused:
        charge_api.delete_charge_log(live_id, db=db, current_user=user)
    assert refused.value.status_code == 409
    assert _row(db, live_id) is not None
    assert manager.active_sessions["CAR1"].charge_log_id == live_id

    # An open row nobody records any more is not in progress, and goes.
    response = charge_api.delete_charge_log(orphan_id, db=db, current_user=user)
    assert response.status_code == 204
    assert _row(db, orphan_id) is None
