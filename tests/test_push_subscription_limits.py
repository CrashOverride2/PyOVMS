"""Push subscriptions are bounded, and the newest ones are the ones that survive.

`device_id` is chosen by the client, so `POST /vehicles/{id}/push/fcm` inserts a new row
for every identifier it has not seen before. The notification fan-out caps how many
recipients one notification reaches, but that cap said nothing about how many rows a
vehicle accumulates — every one of which was then loaded and sorted in Python on every
notification, forever.

Two things are pinned down here: the table stops growing, and the ordering the
dispatcher relies on to pick "the most recently registered" comes from the query rather
than from insertion luck.
"""

import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.crud import push_subscription as crud_sub
from app.database import Base
from app.models import db as models_db
# Vehicle relates to ChargeLog by name; without the module imported the mapper cannot
# resolve it and every query in this file fails at configure time.
from app.services.charge_logger import models as charge_models  # noqa: F401


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()

    owner = models_db.User(username="owner", email="owner@example.com",
                           hashed_password="x", is_active=True)
    session.add(owner)
    session.flush()
    session.add(models_db.Vehicle(
        vehicle_id="CAR1", owner_id=owner.id, protocol="v3",
        encrypted_server_password=b"x",
    ))
    session.commit()

    yield session
    session.close()


def _vehicle_fk(db) -> int:
    return db.query(models_db.Vehicle).filter_by(vehicle_id="CAR1").one().id


def _count(db, fk) -> int:
    return db.query(models_db.PushSubscription).filter_by(vehicle_id_fk=fk).count()


def test_registering_the_same_device_twice_does_not_add_a_row(db):
    fk = _vehicle_fk(db)

    crud_sub.upsert_subscription(db, fk, "device-1", "fcm", "token-a")
    crud_sub.upsert_subscription(db, fk, "device-1", "fcm", "token-b")
    db.commit()

    assert _count(db, fk) == 1
    assert crud_sub.get_subscriptions_for_vehicle(db, fk)[0].endpoint == "token-b"


def test_the_table_stops_growing_at_the_cap(db):
    fk = _vehicle_fk(db)
    over = crud_sub.MAX_SUBSCRIPTIONS_PER_VEHICLE + 15

    for n in range(over):
        crud_sub.upsert_subscription(db, fk, f"device-{n}", "fcm", f"token-{n}")
    db.commit()

    assert _count(db, fk) == crud_sub.MAX_SUBSCRIPTIONS_PER_VEHICLE


def test_the_oldest_registrations_are_the_ones_dropped(db):
    fk = _vehicle_fk(db)
    base = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)

    # Explicit timestamps: several inserts land inside the same clock tick otherwise,
    # and then "oldest" would be decided by the id tiebreak rather than by age.
    for n in range(crud_sub.MAX_SUBSCRIPTIONS_PER_VEHICLE + 5):
        sub = crud_sub.upsert_subscription(db, fk, f"device-{n}", "fcm", f"token-{n}")
        sub.created_at = base + datetime.timedelta(minutes=n)
        db.flush()
    db.commit()

    surviving = {s.device_id for s in crud_sub.get_subscriptions_for_vehicle(db, fk)}
    assert "device-0" not in surviving, "an old registration outlived a newer one"
    assert f"device-{crud_sub.MAX_SUBSCRIPTIONS_PER_VEHICLE + 4}" in surviving


def test_the_query_returns_newest_first_and_honours_the_limit(db):
    fk = _vehicle_fk(db)
    base = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)

    for n in range(5):
        sub = crud_sub.upsert_subscription(db, fk, f"device-{n}", "fcm", f"token-{n}")
        sub.created_at = base + datetime.timedelta(minutes=n)
    db.commit()

    newest_two = crud_sub.get_subscriptions_for_vehicle(db, fk, limit=2)
    assert [s.device_id for s in newest_two] == ["device-4", "device-3"]
    assert len(crud_sub.get_subscriptions_for_vehicle(db, fk)) == 5


def test_manual_recipients_are_capped_too(db):
    """The e-mail and ntfy recipients an owner adds by hand go through the same door."""
    fk = _vehicle_fk(db)

    for n in range(crud_sub.MAX_SUBSCRIPTIONS_PER_VEHICLE + 10):
        crud_sub.add_manual_email(db, fk, f"recipient{n}@example.com")
    db.commit()

    assert _count(db, fk) == crud_sub.MAX_SUBSCRIPTIONS_PER_VEHICLE
