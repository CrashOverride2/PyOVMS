"""
The SQL and the timestamp handling have to mean the same thing on every backend.

Two defects of the same shape, both invisible to a suite that runs on SQLite:

  * `func.group_concat(...)` compiles to a literal `group_concat(...)` for whatever
    dialect is bound. PostgreSQL has no such function, so V2 command 30 answered with
    UndefinedFunction there and worked perfectly everywhere it was ever tested.

  * `value.astimezone(tz)` on a *naive* datetime reads it as system local time, not as
    UTC. SQLite has no timezone type, so every stored timestamp comes back naive, and
    the datalog chart labels were shifted by the server's UTC offset — on SQLite only,
    which is why the same page was correct on PostgreSQL.

Neither can be caught by executing against SQLite, so neither is tested that way:
the first compiles the statement for each dialect, the second reads the source.
"""

import ast
import datetime
import pathlib

import pytest
from sqlalchemy.dialects import mysql, postgresql, sqlite

from app.crud import historical_data as crud_history
from app.database import Base, SessionLocal, connect_args_for, engine
from app.models import db as models_db
# Vehicle has a relationship() to ChargeLog, so the mappers do not configure
# until this module is imported.
from app.services.charge_logger import models as charge_models  # noqa: F401

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
APP_DIR = REPO_ROOT / "app"

DIALECTS = {
    "sqlite": sqlite.dialect(),
    "postgresql": postgresql.dialect(),
    "mysql": mysql.dialect(),
}


@pytest.fixture(scope="module", autouse=True)
def _schema():
    Base.metadata.create_all(bind=engine)
    yield


# --- the aggregate, compiled for each backend ------------------------------------

@pytest.mark.parametrize("name,expected", [
    ("sqlite", "group_concat"),
    ("mysql", "group_concat"),
    ("postgresql", "string_agg"),
])
def test_payload_concat_uses_the_name_the_backend_has(name, expected):
    sql = str(crud_history.payload_concat(name).compile(dialect=DIALECTS[name]))

    assert expected in sql, f"{name} got {sql!r}"


def test_postgresql_never_emits_group_concat():
    """The regression itself. PostgreSQL has no group_concat; the error is at runtime."""
    sql = str(
        crud_history.payload_concat("postgresql").compile(dialect=DIALECTS["postgresql"])
    )

    assert "group_concat" not in sql


def test_postgresql_names_the_separator():
    """string_agg has no default; without it the payloads would run together."""
    compiled = crud_history.payload_concat("postgresql").compile(
        dialect=DIALECTS["postgresql"], compile_kwargs={"literal_binds": True}
    )

    assert "','" in str(compiled)


def test_an_unknown_dialect_falls_back_rather_than_failing():
    """A backend nobody anticipated gets the spelling two of the three share."""
    sql = str(crud_history.payload_concat("firebird").compile(dialect=DIALECTS["sqlite"]))

    assert "group_concat" in sql


# --- and still does the right thing where it can actually run ---------------------

def test_the_daily_rollup_joins_a_days_payloads_with_commas():
    """The SQLite half of the same function, so the refactor is not taken on trust."""
    db = SessionLocal()
    try:
        user = models_db.User(username="dialect-owner", email="dialect@example.com",
                              hashed_password="x", is_active=True)
        db.add(user)
        db.commit()
        db.refresh(user)
        vehicle = models_db.Vehicle(vehicle_id="DIALECTTEST", owner_id=user.id,
                                    protocol="both", encrypted_server_password=b"x")
        db.add(vehicle)
        db.commit()
        db.refresh(vehicle)

        day = datetime.datetime(2026, 3, 4, tzinfo=datetime.timezone.utc)
        for n, payload in enumerate(("11,22", "33,44")):
            db.add(models_db.HistoricalData(
                vehicle_id_fk=vehicle.id, vehicle_module_id_str="DIALECTTEST",
                record_type="*-OVM-Utilisation", record_number=n, data_payload=payload,
                timestamp=day + datetime.timedelta(hours=n),
            ))
        db.commit()

        rows = crud_history.get_historical_daily(db, "DIALECTTEST")

        assert len(rows) == 1
        assert rows[0]["u_date"] == "2026-03-04"
        assert set(rows[0]["data"].split(",")) == {"11", "22", "33", "44"}
    finally:
        db.rollback()
        db.query(models_db.HistoricalData).filter(
            models_db.HistoricalData.vehicle_module_id_str == "DIALECTTEST"
        ).delete(synchronize_session=False)
        db.query(models_db.Vehicle).filter(
            models_db.Vehicle.vehicle_id == "DIALECTTEST"
        ).delete(synchronize_session=False)
        db.query(models_db.User).filter(
            models_db.User.username == "dialect-owner"
        ).delete(synchronize_session=False)
        db.commit()
        db.close()


# --- naive timestamps must be labelled before they are converted ------------------

def _astimezone_receivers():
    """Every `<something>.astimezone(...)` in app/, with what it was called on.

    The receiver is what decides correctness: a value read straight off an ORM row is
    naive on SQLite and aware on PostgreSQL, so converting it without labelling it
    first gives two different answers from the same code.
    """
    for path in sorted(APP_DIR.rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "astimezone"):
                yield path.relative_to(REPO_ROOT), node.lineno, node.func.value


def test_no_orm_timestamp_is_converted_before_it_is_labelled():
    """
    An attribute receiver — `record.timestamp.astimezone(tz)` — is the dangerous form:
    it is a column value, so it is naive on SQLite, and astimezone() will read it as
    system local time. Wrap it in as_utc() (app/utils/timestamps.py).

    A plain name is allowed: the code is holding a local it has already normalised,
    which is what the Jinja filter in ui/__init__.py does two lines before its call.
    """
    offenders = [
        f"{path}:{lineno}"
        for path, lineno, receiver in _astimezone_receivers()
        if isinstance(receiver, ast.Attribute)
    ]

    assert offenders == [], (
        "these convert a stored timestamp without labelling it UTC first, so they are "
        "off by the server's UTC offset on SQLite and correct on PostgreSQL: "
        + ", ".join(offenders)
    )


def test_the_scan_still_finds_the_calls_it_guards():
    """A guard whose subject silently becomes an empty set passes forever."""
    assert len(list(_astimezone_receivers())) >= 3


# --- the connection itself must agree on what "now" means ------------------------

@pytest.mark.parametrize("url", [
    "postgresql://u@h/d",
    "postgresql+psycopg2://u@h/d",
])
def test_postgresql_sessions_are_pinned_to_utc(url):
    """
    `timestamptz` is returned in the *session's* TimeZone, which defaults to whatever
    the server, database or role is set to. Everything that converts survives that
    (as_utc handles any offset); everything that formats a value it already believes
    to be UTC does not, and neither does date_trunc(), which would then cut months on
    local boundaries on PostgreSQL and on UTC boundaries on SQLite.
    """
    assert connect_args_for(url) == {"options": "-c timezone=UTC"}


def test_sqlite_still_gets_the_cross_thread_argument():
    """The TCP servers, the MQTT subscribers and the broadcaster share one engine."""
    assert connect_args_for("sqlite:///./ovms_py.db") == {"check_same_thread": False}


def test_mysql_gets_no_timezone_option():
    """`-c timezone=UTC` is libpq syntax; MySQL reads DATETIME back naive anyway."""
    assert connect_args_for("mysql+pymysql://u@h/d") == {}


# --- a written zone designator is a claim, and has to be true ---------------------

def _zone_asserting_strftime_calls():
    """Every `X.strftime(fmt)` in app/ whose fmt states which zone the value is in.

    Read as AST, not as text: app/database.py quotes one of these formats in prose to
    explain the hazard, and a line-based scan reports the explanation as the defect.
    """
    for path in sorted(APP_DIR.rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "strftime"
                    and node.args
                    and isinstance(node.args[0], ast.Constant)
                    and isinstance(node.args[0].value, str)):
                continue
            fmt = node.args[0].value
            if fmt.endswith("Z") or "UTC" in fmt:
                yield path.relative_to(REPO_ROOT), node.lineno, node.func.value


def _is_already_utc(receiver) -> bool:
    """True when the formatted value is demonstrably in UTC at this call site."""
    if not isinstance(receiver, ast.Call):
        return False
    # as_utc(...) — the shared normaliser.
    if isinstance(receiver.func, ast.Name) and receiver.func.id == "as_utc":
        return True
    # datetime.now(timezone.utc) — already in the zone it claims, nothing stored.
    return isinstance(receiver.func, ast.Attribute) and receiver.func.attr in {"now", "astimezone"}


def test_every_written_zone_designator_was_actually_converted():
    """
    Writing `...Z` or `... UTC` asserts a zone. The value must have been put in that
    zone first — via as_utc() — or the string is a statement about an instant that is
    false by the server's UTC offset.

    A literal `datetime.now(timezone.utc)` is exempt: it is already in the zone it
    claims, and there is nothing stored about it.
    """
    offenders = [
        f"{path}:{lineno}"
        for path, lineno, receiver in _zone_asserting_strftime_calls()
        if not _is_already_utc(receiver)
    ]

    assert offenders == [], (
        "these write a zone designator onto a value they never converted, so on a "
        "PostgreSQL session that is not UTC they label a local wall clock as UTC: "
        + ", ".join(offenders)
    )


def test_the_zone_designator_scan_still_finds_the_calls_it_guards():
    assert len(list(_zone_asserting_strftime_calls())) >= 4


# --- the config backup payload has to be as wide on MySQL as everywhere else ------

@pytest.mark.parametrize("name,expected", [
    ("sqlite", "TEXT"),
    ("postgresql", "TEXT"),
    ("mysql", "LONGTEXT"),
])
def test_config_backup_payload_column_is_wide_enough_on_every_backend(name, expected):
    """
    A bare `Text` is 64 KiB on MySQL and unbounded on the other two. The app's backup
    document is JSON text that a user with several vehicles and a few dozen commands
    pushes past that, and MySQL truncates silently — the row is stored, the JSON is
    cut mid-string, and the app finds out on restore.
    """
    from sqlalchemy.schema import CreateTable

    ddl = str(CreateTable(models_db.ConfigBackup.__table__).compile(dialect=DIALECTS[name]))
    payload_line = next(line for line in ddl.splitlines() if "payload " in line)

    assert expected in payload_line, f"{name}: {payload_line.strip()!r}"
    if name != "mysql":
        assert "LONGTEXT" not in payload_line


@pytest.mark.parametrize("name", list(DIALECTS))
def test_the_auto_eviction_query_compiles_on_every_backend(name):
    """OFFSET without LIMIT is spelled three different ways; SQLAlchemy knows them,
    provided the query is built the way it expects. Compiling is the cheap proof."""
    from app.crud import config_backup as crud_backup

    db = SessionLocal()
    try:
        query = crud_backup.stale_auto_ids_query(db, owner_id=1, device_id="abcd")
        sql = str(query.statement.compile(dialect=DIALECTS[name]))
    finally:
        db.close()

    assert "config_backups" in sql
    assert "OFFSET" in sql.upper() or "LIMIT" in sql.upper()



@pytest.mark.parametrize("name", list(DIALECTS))
def test_the_device_window_query_compiles_on_every_backend(name):
    """Grouped by device and ordered by an aggregate — MySQL's ONLY_FULL_GROUP_BY
    and PostgreSQL both accept ordering by the aggregate expression itself, but
    not by a column outside the GROUP BY; compiling shows which one was written."""
    from app.crud import config_backup as crud_backup

    db = SessionLocal()
    try:
        query = crud_backup.auto_windows_by_staleness_query(db, owner_id=1)
        sql = str(query.statement.compile(dialect=DIALECTS[name]))
    finally:
        db.close()

    assert "GROUP BY config_backups.device_id" in sql
    assert "ORDER BY max(config_backups.created_at)" in sql


@pytest.mark.parametrize("name", list(DIALECTS))
def test_the_command_favorites_query_compiles_on_every_backend(name):
    """Ordered by a column called `position` — a name that is reserved or a function
    in more than one SQL dialect. Compiling shows whether it needs quoting anywhere;
    the migration and the model spell it bare."""
    from app.crud import command_favorite as crud_favorite

    db = SessionLocal()
    try:
        query = crud_favorite.favorites_query(db, owner_id=1)
        sql = str(query.statement.compile(dialect=DIALECTS[name]))
    finally:
        db.close()

    assert "ORDER BY command_favorites.position, command_favorites.id" in sql


@pytest.mark.parametrize("name, locks", [("sqlite", False), ("postgresql", True), ("mysql", True)])
def test_the_owner_lock_is_a_row_lock_where_the_backend_has_one(name, locks):
    """store_backup() serialises a user's writers with SELECT ... FOR UPDATE on
    their users row. SQLite has no row locks and one writer per database, so the
    clause must vanish there rather than fail."""
    from sqlalchemy import select

    from app.models import db as models_db

    statement = select(models_db.User.id).where(models_db.User.id == 1).with_for_update()
    sql = str(statement.compile(dialect=DIALECTS[name]))
    assert ("FOR UPDATE" in sql) is locks, sql
