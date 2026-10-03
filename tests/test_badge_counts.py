"""The badge a push carries: counted per vehicle, sent as the owner's total."""

import threading

import pytest

from app.database import Base, SessionLocal, engine
from app.models import db as models_db
from app.services.charge_logger import models as _charge_models  # noqa: F401 - Vehicle's relationships
from app.widget_push_service import BadgeService


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
    db.query(models_db.Vehicle).delete()
    db.query(models_db.User).delete()
    db.commit()
    yield


def _user(db, name):
    user = models_db.User(username=name, email=f"{name}@example.com",
                          hashed_password="x", is_active=True)
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _vehicle(db, owner, vehicle_id, badge=0):
    vehicle = models_db.Vehicle(vehicle_id=vehicle_id, owner_id=owner.id, protocol="both",
                                encrypted_server_password=b"x", badge_count=badge)
    db.add(vehicle)
    db.commit()
    return vehicle


def _stored(db, vehicle_id):
    db.expire_all()
    return db.query(models_db.Vehicle).filter_by(vehicle_id=vehicle_id).one().badge_count


def test_the_badge_sent_is_the_total_over_the_owners_vehicles(db):
    owner = _user(db, "owner")
    other = _user(db, "other")
    _vehicle(db, owner, "CARA", badge=3)
    _vehicle(db, owner, "CARB")
    _vehicle(db, other, "CARC", badge=9)

    assert BadgeService().increment_badge_count("CARB") == 4
    assert BadgeService().increment_badge_count("cara") == 5
    assert _stored(db, "CARA") == 4
    assert _stored(db, "CARB") == 1
    assert _stored(db, "CARC") == 9


def test_an_unknown_vehicle_counts_nothing(db):
    assert BadgeService().increment_badge_count("NOPE") is None


def test_the_reset_clears_the_total(db):
    owner = _user(db, "owner")
    _vehicle(db, owner, "CARA", badge=3)
    _vehicle(db, owner, "CARB", badge=2)

    assert BadgeService().reset_all_badge_counts_for_user(owner.id) == 2
    assert BadgeService().increment_badge_count("CARA") == 1


def test_concurrent_increments_are_not_lost(db):
    owner = _user(db, "owner")
    _vehicle(db, owner, "CARA")
    service = BadgeService()

    threads = [threading.Thread(target=service.increment_badge_count, args=("CARA",))
               for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert _stored(db, "CARA") == 8
