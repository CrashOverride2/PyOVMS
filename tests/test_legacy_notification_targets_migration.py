"""c6d7e8f9a0b1: the vehicle-level notification targets become subscriptions, or go.

The migration decides, per vehicle, which of the old columns were still an intended
target and which were the shadow of an app registration. Getting that wrong either way
is invisible until a notification is missing — or arrives twice, which is the bug that
made the columns go: a phone that switched from FCM to UnifiedPush kept receiving FCM
through the vehicle copy of its old token.

Runs the real `upgrade()`/`downgrade()` against a scratch SQLite file with the old
schema, not against the suite's shared database: Alembic's env.py binds to the app's
engine, and the migration drops columns.
"""
import datetime
import importlib.util
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations

_MIGRATION = (
    Path(__file__).resolve().parent.parent
    / "alembic" / "versions" / "c6d7e8f9a0b1_legacy_notification_targets_to_subscriptions.py"
)


@pytest.fixture(scope="module")
def migration():
    spec = importlib.util.spec_from_file_location("legacy_targets_migration", _MIGRATION)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _legacy_row(**overrides):
    row = {
        "id": 1,
        "enable_ntfy_notifications": False, "ntfy_topic": None, "ntfy_server_url": None,
        "ntfy_auth_method": None, "ntfy_auth_token": None, "ntfy_auth_user": None,
        "ntfy_auth_password": None, "ntfy_auth_query_param_name": None,
        "enable_email_notifications": False, "notification_email": None,
        "enable_fcm_notifications": False, "fcm_token": None,
        "enable_apns_notifications": False, "apns_token": None,
        "enable_unified_push_notifications": False, "unified_push_endpoint": None,
    }
    row.update(overrides)
    return row


_NOW = datetime.datetime(2026, 10, 2, tzinfo=datetime.timezone.utc)


def _planned(migration, row, existing=(), default_topic="server-default"):
    rows = migration.plan_subscriptions(row, set(existing), default_topic, _NOW)
    return sorted((r["push_type"], r["device_id"], r["endpoint"]) for r in rows)


# ---------------------------------------------------------------------------
# the rules
# ---------------------------------------------------------------------------

def test_a_token_left_behind_by_a_switch_to_unifiedpush_is_dropped(migration):
    """The case that made the columns go: FCM once, UnifiedPush now. The vehicle copy
    of the FCM token is a shadow, not a target, and must not become one."""
    row = _legacy_row(enable_fcm_notifications=True, fcm_token="old-fcm-token")
    assert _planned(migration, row, existing={"up"}) == []


@pytest.mark.parametrize("existing", [{"fcm"}, {"apns"}, {"up"}])
def test_any_app_registration_retires_every_mobile_copy(migration, existing):
    row = _legacy_row(
        enable_fcm_notifications=True, fcm_token="f",
        enable_apns_notifications=True, apns_token="a",
        enable_unified_push_notifications=True, unified_push_endpoint="https://up/x",
    )
    assert _planned(migration, row, existing=existing) == []


def test_mobile_targets_of_a_vehicle_without_registrations_are_kept(migration):
    row = _legacy_row(
        enable_fcm_notifications=True, fcm_token="f",
        enable_apns_notifications=True, apns_token="a",
        enable_unified_push_notifications=True, unified_push_endpoint="https://up/x",
    )
    assert _planned(migration, row, existing={"email", "ntfy"}) == [
        ("apns", "legacy", "a"),
        ("fcm", "legacy", "f"),
        ("up", "legacy", "https://up/x"),
    ]


def test_a_disabled_or_empty_target_is_not_carried_over(migration):
    row = _legacy_row(
        enable_fcm_notifications=False, fcm_token="f",
        enable_email_notifications=True, notification_email="  ",
        enable_apns_notifications=True, apns_token=None,
    )
    assert _planned(migration, row) == []


def test_ntfy_keeps_its_topic_or_takes_the_default_the_fallback_used(migration):
    own = _legacy_row(enable_ntfy_notifications=True, ntfy_topic="my-topic",
                      ntfy_server_url="https://ntfy.example", ntfy_auth_method="token",
                      ntfy_auth_token=b"encrypted")
    rows = migration.plan_subscriptions(own, set(), "server-default", _NOW)
    assert [(r["device_id"], r["endpoint"]) for r in rows] == [("my-topic", "my-topic")]
    # The credentials are copied as stored: both tables hold them under the same key.
    assert rows[0]["ntfy_auth_token"] == b"encrypted"
    assert rows[0]["ntfy_server_url"] == "https://ntfy.example"

    default = _legacy_row(enable_ntfy_notifications=True, ntfy_topic=None)
    assert _planned(migration, default) == [("ntfy", "server-default", "server-default")]
    assert _planned(migration, default, default_topic="") == []


def test_manual_channels_yield_to_a_subscription_of_their_own_type(migration):
    row = _legacy_row(enable_ntfy_notifications=True, ntfy_topic="old",
                      enable_email_notifications=True, notification_email="old@example.com")
    assert _planned(migration, row, existing={"ntfy", "email"}) == []
    # ...but not to an app registration: they are separate targets.
    assert _planned(migration, row, existing={"fcm"}) == [
        ("email", "old@example.com", "old@example.com"),
        ("ntfy", "old", "old"),
    ]


def test_every_planned_row_has_the_same_keys(migration):
    """bulk_insert is one executemany compiled from one row. On PostgreSQL a row with a
    key fewer failed the whole migration (an FCM row after an ntfy row, in production);
    on SQLite the first row's keys win and a later ntfy row lost its credentials."""
    row = _legacy_row(
        enable_fcm_notifications=True, fcm_token="f",
        enable_ntfy_notifications=True, ntfy_topic="t", ntfy_server_url="https://ntfy.example",
        enable_email_notifications=True, notification_email="a@example.com",
    )
    rows = migration.plan_subscriptions(row, set(), "server-default", _NOW)
    assert len(rows) == 3
    assert len({frozenset(r) for r in rows}) == 1


# ---------------------------------------------------------------------------
# the migration itself
# ---------------------------------------------------------------------------

def _old_schema(engine, migration):
    meta = sa.MetaData()
    sa.Table(
        "vehicles", meta,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("vehicle_id", sa.String(32), unique=True, nullable=False),
        sa.Column("vehicle_name", sa.String(100)),
        *(sa.Column(name, type_, nullable=True) for name, type_, _ in migration._LEGACY_COLUMNS),
    )
    sa.Table(
        "push_subscriptions", meta,
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("vehicle_id_fk", sa.Integer, sa.ForeignKey("vehicles.id", ondelete="CASCADE"), nullable=False),
        sa.Column("device_id", sa.String(255), nullable=False),
        sa.Column("push_type", sa.String(10), nullable=False),
        sa.Column("endpoint", sa.String(500), nullable=False),
        sa.Column("ntfy_server_url", sa.String(255)),
        sa.Column("ntfy_auth_method", sa.String(50)),
        sa.Column("ntfy_auth_token", sa.LargeBinary),
        sa.Column("ntfy_auth_user", sa.String(100)),
        sa.Column("ntfy_auth_password", sa.LargeBinary),
        sa.Column("ntfy_auth_query_param_name", sa.String(50)),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("vehicle_id_fk", "device_id", "push_type"),
    )
    meta.create_all(engine)
    return meta


def _run(engine, step):
    with engine.begin() as conn:
        with Operations.context(MigrationContext.configure(conn)):
            step()


def test_upgrade_moves_live_targets_and_drops_the_columns(tmp_path, migration, monkeypatch):
    monkeypatch.setattr(migration, "_default_ntfy_topic", lambda: "server-default")
    engine = sa.create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    meta = _old_schema(engine, migration)
    vehicles, subs = meta.tables["vehicles"], meta.tables["push_subscriptions"]

    with engine.begin() as conn:
        for vehicle in [
            # Switched from FCM to UnifiedPush: the FCM copy must not come back.
            {"id": 1, "vehicle_id": "NIU", "vehicle_name": "Scooter",
             "enable_fcm_notifications": True, "fcm_token": "stale-fcm",
             "enable_unified_push_notifications": True, "unified_push_endpoint": "https://up/niu"},
            # Never registered through the API: everything it has is a live target.
            {"id": 2, "vehicle_id": "OLD", "vehicle_name": None,
             "enable_fcm_notifications": True, "fcm_token": "v2-token",
             "enable_ntfy_notifications": True, "ntfy_topic": None,
             "ntfy_server_url": "https://ntfy.example", "ntfy_auth_method": "token",
             "ntfy_auth_token": b"encrypted-token",
             "enable_email_notifications": True, "notification_email": "owner@example.com"},
        ]:
            conn.execute(vehicles.insert(), vehicle)
        conn.execute(subs.insert(), [
            {"vehicle_id_fk": 1, "device_id": "phone", "push_type": "up",
             "endpoint": "https://up/niu", "created_at": _NOW, "updated_at": _NOW},
        ])

    _run(engine, migration.upgrade)

    with engine.connect() as conn:
        rows = conn.execute(sa.text(
            "SELECT vehicle_id_fk, push_type, device_id, endpoint FROM push_subscriptions "
            "ORDER BY vehicle_id_fk, push_type"
        )).fetchall()
        ntfy = conn.execute(sa.text(
            "SELECT ntfy_server_url, ntfy_auth_method, ntfy_auth_token FROM push_subscriptions "
            "WHERE push_type = 'ntfy'"
        )).fetchone()
        columns = {c["name"] for c in sa.inspect(conn).get_columns("vehicles")}
        kept = conn.execute(sa.text("SELECT vehicle_id, vehicle_name FROM vehicles ORDER BY id")).fetchall()

    assert [tuple(r) for r in rows] == [
        (1, "up", "phone", "https://up/niu"),
        (2, "email", "owner@example.com", "owner@example.com"),
        (2, "fcm", "legacy", "v2-token"),
        (2, "ntfy", "server-default", "server-default"),
    ]
    # Planned after the FCM row of the same vehicle: the case that lost its fields.
    assert tuple(ntfy) == ("https://ntfy.example", "token", b"encrypted-token")
    assert columns == {"id", "vehicle_id", "vehicle_name"}
    assert [tuple(r) for r in kept] == [("NIU", "Scooter"), ("OLD", None)]


def test_downgrade_restores_the_columns_empty(tmp_path, migration, monkeypatch):
    monkeypatch.setattr(migration, "_default_ntfy_topic", lambda: "")
    engine = sa.create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    meta = _old_schema(engine, migration)
    with engine.begin() as conn:
        conn.execute(meta.tables["vehicles"].insert(), [{"id": 1, "vehicle_id": "CAR"}])

    _run(engine, migration.upgrade)
    _run(engine, migration.downgrade)

    with engine.connect() as conn:
        columns = {c["name"] for c in sa.inspect(conn).get_columns("vehicles")}
        flags = conn.execute(sa.text(
            "SELECT enable_fcm_notifications, enable_apns_notifications, fcm_token FROM vehicles"
        )).fetchone()

    assert {name for name, _t, _n in migration._LEGACY_COLUMNS} <= columns
    assert tuple(flags) == (0, 0, None)
