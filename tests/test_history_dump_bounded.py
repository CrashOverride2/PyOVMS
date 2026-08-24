"""
H-14 — the V2 app command 32 must not be an OOM primitive.

`get_historical_data_for_vehicle(..., limit=None)` materialised every matching row as
an ORM object. The per-vehicle cap is 10 000 rows x 64 KiB, so one request from any
authenticated app connection could pull roughly 640 MB into memory, and nothing
stopped it being repeated as fast as the socket allowed.

The fix deliberately does NOT cap the row count: the reply carries "record k of n" and
clients expect the complete set, exactly as the original Perl server delivered it.
Compatibility with the legacy app is the constraint, so the bound is on *memory and
repetition*, not on the answer:

  * count first, then stream with yield_per() — one batch resident instead of all rows
  * a minimum interval per connection for commands 30/31/32

The first test therefore pins the wire format, so a later attempt to "just add a
limit" fails here rather than in the field.
"""

import asyncio
import datetime
import inspect

import pytest

from app.connection_manager import ClientConnection
from app.crud import historical_data as crud_history
from app.database import Base, SessionLocal, engine
from app.models import db as models_db
from app.protocols.v2 import handlers


@pytest.fixture(scope="module", autouse=True)
def _schema():
    Base.metadata.create_all(bind=engine)
    yield


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(autouse=True)
def _clean(db):
    db.query(models_db.HistoricalData).delete()
    db.query(models_db.Vehicle).delete()
    db.query(models_db.User).delete()
    db.commit()
    yield


def _vehicle_with_history(db, rows, vehicle_id="CAR1", record_type="*-LOG-Trip"):
    user = models_db.User(
        username="owner", email="owner@example.com",
        hashed_password="x", is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    vehicle = models_db.Vehicle(
        vehicle_id=vehicle_id, owner_id=user.id, protocol="both",
        encrypted_server_password=b"x",
    )
    db.add(vehicle)
    db.commit()

    db.refresh(vehicle)

    base = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    for i in range(rows):
        db.add(models_db.HistoricalData(
            vehicle_id_fk=vehicle.id,
            vehicle_module_id_str=vehicle_id,
            record_type=record_type,
            record_number=i,
            data_payload=f"payload-{i}",
            timestamp=base + datetime.timedelta(minutes=i),
        ))
    db.commit()
    return vehicle


class _FakeConn:
    """Captures what command 32 would put on the wire."""

    def __init__(self, vehicle_id="CAR1"):
        self.vehicle_id = vehicle_id
        self.addr_str = "10.0.0.9:1234"
        self.last_history_command_at = 0.0
        self.sent = []

    async def send_encrypted_message(self, code, data):
        self.sent.append((code, data))


def _command32(record_type="*-LOG-Trip", since=None):
    """Built through the real parser, so the tests exercise the wire payload."""
    from app.models.protocol import AppCommandMessageData

    payload = f"32,{record_type}" + (f",{since}" if since else "")
    return AppCommandMessageData.model_validate(payload)


# ---------------------------------------------------------------------------
# The wire format must not change — this is the legacy-app constraint
# ---------------------------------------------------------------------------


def test_command32_still_returns_every_record(db):
    """No silent truncation. A cap here would make clients believe they had it all."""
    _vehicle_with_history(db, rows=25)
    conn = _FakeConn()

    asyncio.run(handlers._handle_app_command_message(conn, _command32(), db))

    assert len(conn.sent) == 25


def test_command32_reports_the_true_total_in_every_line(db):
    """
    The reply is '32,0,{k},{n},...'. n must be the real total and k must run 1..n —
    that pairing is what lets a client know when it has the whole set.
    """
    _vehicle_with_history(db, rows=12)
    conn = _FakeConn()

    asyncio.run(handlers._handle_app_command_message(conn, _command32(), db))

    for index, (code, payload) in enumerate(conn.sent, 1):
        assert code == 'c'
        fields = payload.split(',')
        assert fields[0] == '32'
        assert fields[1] == '0'
        assert int(fields[2]) == index
        assert int(fields[3]) == 12


def test_command32_keeps_oldest_first_ordering(db):
    """Ascending by timestamp, matching the Perl server the clients were written for."""
    _vehicle_with_history(db, rows=8)
    conn = _FakeConn()

    asyncio.run(handlers._handle_app_command_message(conn, _command32(), db))

    timestamps = [payload.split(',')[5] for _, payload in conn.sent]
    assert timestamps == sorted(timestamps)


def test_command32_reports_empty_history_unchanged(db):
    _vehicle_with_history(db, rows=0)
    conn = _FakeConn()

    asyncio.run(handlers._handle_app_command_message(conn, _command32(), db))

    assert conn.sent == [('c', "32,1,No historical data available")]


# ---------------------------------------------------------------------------
# The actual fix: bounded memory, bounded repetition
# ---------------------------------------------------------------------------


def test_command32_streams_instead_of_materialising(db):
    """
    The property that fixes the OOM, asserted behaviourally rather than by poking at
    SQLAlchemy internals: consume a single record out of 60 with a batch size of 10
    and count what actually landed in the session. Streaming loads one batch; .all()
    loads all 60 before the first item is handed back.
    """
    _vehicle_with_history(db, rows=60)
    db.expunge_all()

    stream = crud_history.iter_historical_data_for_vehicle(
        db, "CAR1", record_type_equals="*-LOG-Trip", sort_ascending=True, batch_size=10,
    )
    assert not isinstance(stream, list), "reader still materialises the whole result"

    iterator = iter(stream)
    next(iterator)

    resident = len([o for o in db.identity_map.values() if isinstance(o, models_db.HistoricalData)])
    assert resident < 60, f"reader loaded all 60 rows before yielding the first ({resident})"
    assert resident <= 20, f"batch size is not being honoured ({resident} rows resident)"


def test_command32_handler_does_not_call_the_materialising_reader(db):
    """
    Guards the call site, not just the helper. Adding a streaming function while the
    handler kept calling .all() would leave the bug in place — the exact shape of the
    H-4 regression, where a correct fix sat next to code that bypassed it.
    """
    source = inspect.getsource(handlers._handle_app_command_message)
    command32 = source[source.index("command_code == 32"):]

    assert "iter_historical_data_for_vehicle" in command32
    assert "get_historical_data_for_vehicle" not in command32, (
        "command 32 still uses the materialising reader"
    )


def test_count_matches_what_gets_streamed(db):
    """The 'n' in the reply comes from a separate query; the two must not disagree."""
    _vehicle_with_history(db, rows=17)

    total = crud_history.count_historical_data_for_vehicle(
        db, "CAR1", record_type_equals="*-LOG-Trip"
    )
    streamed = list(crud_history.iter_historical_data_for_vehicle(
        db, "CAR1", record_type_equals="*-LOG-Trip", sort_ascending=True
    ))

    assert total == len(streamed) == 17


def test_filters_apply_to_count_and_stream_alike(db):
    """A filter that reached only one of the two would desynchronise k and n."""
    _vehicle_with_history(db, rows=10)
    cutoff = datetime.datetime(2026, 1, 1, 0, 4, tzinfo=datetime.timezone.utc)

    total = crud_history.count_historical_data_for_vehicle(
        db, "CAR1", record_type_equals="*-LOG-Trip", since_date=cutoff
    )
    streamed = list(crud_history.iter_historical_data_for_vehicle(
        db, "CAR1", record_type_equals="*-LOG-Trip", since_date=cutoff, sort_ascending=True
    ))

    assert total == len(streamed) == 5


def test_repeated_history_commands_are_throttled(db):
    """Each repeat walks the whole table again; one per 5 s is generous for a UI."""
    _vehicle_with_history(db, rows=3)
    conn = _FakeConn()

    asyncio.run(handlers._handle_app_command_message(conn, _command32(), db))
    first = len(conn.sent)
    conn.sent.clear()

    asyncio.run(handlers._handle_app_command_message(conn, _command32(), db))

    assert first == 3
    assert conn.sent == [('c', "32,1,Too many history requests, please wait")]


def test_throttle_releases_after_the_interval(db):
    """A throttle that never released would break the legitimate history view."""
    _vehicle_with_history(db, rows=3)
    conn = _FakeConn()

    asyncio.run(handlers._handle_app_command_message(conn, _command32(), db))
    conn.sent.clear()
    conn.last_history_command_at -= handlers._HISTORY_COMMAND_MIN_INTERVAL_SECONDS + 1

    asyncio.run(handlers._handle_app_command_message(conn, _command32(), db))

    assert len(conn.sent) == 3


def test_throttle_is_per_connection(db):
    """Sharing one counter across connections would let one client mute another."""
    _vehicle_with_history(db, rows=3)
    first, second = _FakeConn(), _FakeConn()

    asyncio.run(handlers._handle_app_command_message(first, _command32(), db))
    asyncio.run(handlers._handle_app_command_message(second, _command32(), db))

    assert len(second.sent) == 3


def test_throttle_covers_all_three_history_commands():
    assert set(handlers._HISTORY_COMMAND_CODES) == {30, 31, 32}


def test_connection_exposes_the_throttle_field():
    """Set in __init__ rather than lazily, so the handler cannot read a missing attr."""
    assert "last_history_command_at" in inspect.getsource(ClientConnection.__init__)
