"""
ENABLE_KARTO_TRIP_TRACKING also switches off the Karto call of every vehicle and account
deletion (trigger_karto_vehicle_deletion returns at once). Karto records by
`vehicles.enable_trip_tracking` alone, which the API sets whatever the flag says, so a
Karto beside a server without the flag kept trips no deletion removed — silently. The
start now says so.
"""

import logging

import pytest

from app import bootstrap, database


class _FakeSession:
    def __init__(self, tracked):
        self.tracked = tracked
        self.closed = False

    def query(self, *columns):
        return self

    def filter(self, *criteria):
        return self

    def count(self):
        return self.tracked

    def close(self):
        self.closed = True


@pytest.fixture
def session(monkeypatch):
    holder = {}

    def make(tracked):
        holder["session"] = _FakeSession(tracked)
        monkeypatch.setattr(database, "SessionLocal", lambda: holder["session"])
        return holder["session"]

    return make


@pytest.mark.parametrize("flag, tracked, warned", [
    (False, 2, True),
    (False, 0, False),
    (True, 2, False),
])
def test_the_start_warns_when_trip_deletion_would_skip_karto(
        monkeypatch, caplog, session, flag, tracked, warned):
    monkeypatch.setattr(bootstrap.settings, "ENABLE_KARTO_TRIP_TRACKING", flag)
    fake = session(tracked)

    with caplog.at_level(logging.WARNING, logger=bootstrap.module_logger.name):
        bootstrap._check_trip_deletion_reaches_karto()

    hits = [r for r in caplog.records if "will NOT delete its trips" in r.getMessage()]
    assert bool(hits) is warned
    if not flag:
        assert fake.closed


def test_the_check_runs_at_startup():
    import inspect

    assert "_check_trip_deletion_reaches_karto()" in inspect.getsource(bootstrap.initialize_services)
