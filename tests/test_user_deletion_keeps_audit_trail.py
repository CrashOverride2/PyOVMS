"""
Deleting a user must succeed, and must not take the audit trail with it.

`security_events` is the only table with a foreign key to `users.id` and no ORM
relationship behind it — vehicles, API keys, auto-provisioning profiles and WebAuthn
credentials all hang off `User` with `cascade="all, delete-orphan"`, so the unit of work
removes them; nothing touched security_events. On PostgreSQL and MySQL, where foreign
keys are enforced, deleting any account that had ever logged in, failed a login, or had
its role changed failed outright:

    ForeignKeyViolation: update or delete on table "users" violates foreign key
    constraint "fk_security_event_user_id" on table "security_events"

The fix is SET NULL rather than CASCADE, in both directions: the constraint carries
`ondelete="SET NULL"` for anything that deletes a row directly, and `delete_user()`
clears the column itself because SQLite does not enforce foreign keys here at all (see
the PRAGMA note in app/database.py) and would otherwise keep a dangling id. The events
survive with their `username` intact — an audit trail that disappears when the account
does records nothing about the accounts worth auditing.

Foreign keys are switched ON for the engine below precisely because the default SQLite
behaviour would let the original bug pass.
"""

import datetime

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app import crud
from app.database import Base
from app.models import db as models_db
from app.services.charge_logger import models as charge_models  # noqa: F401  (maps ChargeLog)


@pytest.fixture()
def fk_enforcing_session():
    """In-memory SQLite with `PRAGMA foreign_keys=ON`, i.e. behaving like PostgreSQL."""
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})

    @event.listens_for(engine, "connect")
    def _enforce_fks(dbapi_connection, _record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _make_user(session, username="doomed"):
    user = models_db.User(
        username=username,
        email=f"{username}@example.invalid",
        hashed_password="not-a-real-hash",
        is_active=True,
        is_admin=False,
    )
    session.add(user)
    session.commit()
    return user


def _make_event(session, user, event_type="login_failure"):
    security_event = models_db.SecurityEvent(
        event_type=event_type,
        severity="warning",
        user_id=user.id,
        username=user.username,
        ip_address="203.0.113.7",
        created_at=datetime.datetime.now(datetime.timezone.utc),
    )
    session.add(security_event)
    session.commit()
    return security_event


def test_user_with_security_events_can_be_deleted(fk_enforcing_session):
    user = _make_user(fk_enforcing_session)
    _make_event(fk_enforcing_session, user)

    assert crud.user.delete_user(fk_enforcing_session, user.id) is not None
    assert fk_enforcing_session.query(models_db.User).count() == 0


def test_security_events_outlive_the_deleted_user(fk_enforcing_session):
    user = _make_user(fk_enforcing_session)
    _make_event(fk_enforcing_session, user, event_type="admin_role_change")
    _make_event(fk_enforcing_session, user, event_type="login_failure")

    crud.user.delete_user(fk_enforcing_session, user.id)

    events = fk_enforcing_session.query(models_db.SecurityEvent).all()
    assert len(events) == 2, "the audit trail must not be cascaded away with the account"
    assert {e.username for e in events} == {"doomed"}, "who did it must stay readable"
    assert all(e.user_id is None for e in events), "the dead id must not be left dangling"


def test_events_of_other_users_are_untouched(fk_enforcing_session):
    doomed = _make_user(fk_enforcing_session, "doomed")
    survivor = _make_user(fk_enforcing_session, "survivor")
    _make_event(fk_enforcing_session, doomed)
    _make_event(fk_enforcing_session, survivor)

    crud.user.delete_user(fk_enforcing_session, doomed.id)

    kept = fk_enforcing_session.query(models_db.SecurityEvent).filter(
        models_db.SecurityEvent.username == "survivor"
    ).one()
    assert kept.user_id == survivor.id


def test_foreign_key_declares_on_delete_set_null():
    """
    The constraint carries the rule too, for deletes that never pass through
    delete_user() — a manual `DELETE FROM users`, or a future code path.
    """
    fk = next(iter(models_db.SecurityEvent.__table__.c.user_id.foreign_keys))
    assert fk.ondelete == "SET NULL", (
        "CASCADE would delete the audit trail with the account; no rule at all is the "
        "ForeignKeyViolation this test exists for"
    )
