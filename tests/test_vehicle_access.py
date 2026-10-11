"""
The one rule for who may reach a vehicle (app/utils/vehicle_access.py).

* the owner always; an admin only while the owner's support grant runs, decided
  by the clock on every call — naive (SQLite) and aware (PostgreSQL) alike;
* a grant made by anyone but the current owner is void;
* administration (edit, delete) stays open to every admin, ownership-only stays
  with the owner even under a grant;
* no route keeps a hand-written `not user.is_admin and … owner_id` copy: that
  pattern was the unconditional admin bypass support mode replaced, and one
  surviving copy is a route where consent does not count.
"""

import datetime
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.utils.vehicle_access import (
    VehicleAccess,
    can_access_vehicle,
    can_administer_vehicle,
    is_vehicle_owner,
    support_active,
    vehicle_access,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
NOW = datetime.datetime(2026, 10, 9, 12, 0, tzinfo=datetime.timezone.utc)

OWNER = SimpleNamespace(id=1, is_admin=False, is_active=True)
ADMIN = SimpleNamespace(id=2, is_admin=True, is_active=True)
STRANGER = SimpleNamespace(id=3, is_admin=False, is_active=True)


def _vehicle(until=None, granted_by=1, owner_id=1):
    return SimpleNamespace(owner_id=owner_id, support_until=until, support_granted_by_id=granted_by)


def test_no_grant_is_not_active():
    assert support_active(_vehicle(None), NOW) is False


def test_a_running_grant_is_active():
    assert support_active(_vehicle(NOW + datetime.timedelta(hours=1)), NOW) is True


def test_a_grant_ends_on_its_time_without_any_sweep():
    assert support_active(_vehicle(NOW), NOW) is False
    assert support_active(_vehicle(NOW - datetime.timedelta(seconds=1)), NOW) is False


def test_a_naive_time_is_read_as_utc():
    """SQLite hands the column back without a zone; it was written as UTC."""
    naive = (NOW + datetime.timedelta(minutes=5)).replace(tzinfo=None)
    assert support_active(_vehicle(naive), NOW) is True
    naive_past = (NOW - datetime.timedelta(minutes=5)).replace(tzinfo=None)
    assert support_active(_vehicle(naive_past), NOW) is False


def test_a_grant_by_someone_other_than_the_owner_is_void():
    assert support_active(_vehicle(NOW + datetime.timedelta(hours=1), granted_by=99), NOW) is False
    assert support_active(_vehicle(NOW + datetime.timedelta(hours=1), granted_by=None), NOW) is False


def test_owner_always_has_access():
    assert vehicle_access(OWNER, _vehicle(None), NOW) is VehicleAccess.OWNER


def test_admin_without_grant_has_no_access():
    assert vehicle_access(ADMIN, _vehicle(None), NOW) is VehicleAccess.NONE
    assert can_access_vehicle(ADMIN, _vehicle(None), NOW) is False


def test_admin_under_a_grant_has_support_access():
    assert vehicle_access(ADMIN, _vehicle(NOW + datetime.timedelta(hours=1)), NOW) is VehicleAccess.SUPPORT


def test_a_grant_opens_nothing_to_a_non_admin():
    assert vehicle_access(STRANGER, _vehicle(NOW + datetime.timedelta(hours=1)), NOW) is VehicleAccess.NONE


def test_an_inactive_admin_gets_nothing():
    inactive = SimpleNamespace(id=4, is_admin=True, is_active=False)
    assert vehicle_access(inactive, _vehicle(NOW + datetime.timedelta(hours=1)), NOW) is VehicleAccess.NONE
    assert can_administer_vehicle(inactive, _vehicle()) is False


def test_an_admin_owning_the_vehicle_is_its_owner():
    """No grant needed, and nothing audited as a support access."""
    assert vehicle_access(ADMIN, _vehicle(None, owner_id=ADMIN.id), NOW) is VehicleAccess.OWNER


def test_administration_is_open_to_every_admin_without_a_grant():
    assert can_administer_vehicle(ADMIN, _vehicle(None)) is True
    assert can_administer_vehicle(OWNER, _vehicle(None)) is True
    assert can_administer_vehicle(STRANGER, _vehicle(None)) is False


def test_owner_only_stays_owner_only_under_a_grant():
    granted = _vehicle(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1))
    assert is_vehicle_owner(OWNER, granted) is True
    assert is_vehicle_owner(ADMIN, granted) is False


def test_missing_vehicle_or_user_is_no_access():
    assert vehicle_access(None, _vehicle(), NOW) is VehicleAccess.NONE
    assert vehicle_access(OWNER, None, NOW) is VehicleAccess.NONE
    assert is_vehicle_owner(OWNER, None) is False
    assert can_administer_vehicle(ADMIN, None) is False


_BYPASS = re.compile(r"not\s+\w+\.is_admin\s+and\s+\w+\.owner_id\s*!=")


@pytest.mark.parametrize("directory", ["app/routers", "app/services/charge_logger", "app/services/event_logger"])
def test_no_hand_written_admin_bypass_remains(directory):
    offenders = []
    for path in (REPO_ROOT / directory).rglob("*.py"):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if _BYPASS.search(line):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{number}: {line.strip()}")
    assert not offenders, "Use app/utils/vehicle_access.py instead:\n" + "\n".join(offenders)
