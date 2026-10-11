"""
Who may do what with a vehicle.

- `can_access_vehicle` — the vehicle's data: the owner, or an admin while the owner's
  support grant runs.
- `can_administer_vehicle` — edit, delete, clear the auto-delete mark: the owner or
  any admin.
- `is_vehicle_owner` — what stays the owner's even under support: the support switch,
  notification targets, the badge, and trips.

Pure functions over ORM rows, no queries. The audit is
`app.services.support_mode.check_vehicle_access`.
"""

import datetime
from enum import Enum
from typing import Optional

from app.utils.timestamps import as_utc


class VehicleAccess(str, Enum):
    NONE = "none"
    OWNER = "owner"
    SUPPORT = "support"


def _inactive(user) -> bool:
    # Only an explicit False: the authentication layer has already refused an
    # inactive account, and a stand-in user in a test carries no flag at all.
    return getattr(user, "is_active", True) is False


def _now(now: Optional[datetime.datetime]) -> datetime.datetime:
    return as_utc(now) if now is not None else datetime.datetime.now(datetime.timezone.utc)


def support_active(vehicle, now: Optional[datetime.datetime] = None) -> bool:
    """True while the owner's support grant on `vehicle` runs.

    Decided by the clock on every call, not by the sweep that clears expired rows:
    access ends at `support_until` even when that pass is a minute behind. A grant
    made by anyone but the current owner is void — there is no ownership transfer
    today, and this keeps a future one from inheriting the previous owner's consent.
    """
    if vehicle is None:
        return False
    until = as_utc(getattr(vehicle, "support_until", None))
    if until is None:
        return False
    if getattr(vehicle, "support_granted_by_id", None) != vehicle.owner_id:
        return False
    return until > _now(now)


def vehicle_access(user, vehicle, now: Optional[datetime.datetime] = None) -> VehicleAccess:
    """How `user` reaches `vehicle`'s data: as its owner, through support, or not.

    An admin who owns the vehicle is its OWNER — no grant needed, nothing audited.
    """
    if user is None or vehicle is None or _inactive(user):
        return VehicleAccess.NONE
    if vehicle.owner_id == user.id:
        return VehicleAccess.OWNER
    if getattr(user, "is_admin", False) and support_active(vehicle, now):
        return VehicleAccess.SUPPORT
    return VehicleAccess.NONE


def can_access_vehicle(user, vehicle, now: Optional[datetime.datetime] = None) -> bool:
    return vehicle_access(user, vehicle, now) is not VehicleAccess.NONE


def can_administer_vehicle(user, vehicle) -> bool:
    if user is None or vehicle is None or _inactive(user):
        return False
    return vehicle.owner_id == user.id or bool(getattr(user, "is_admin", False))


def is_vehicle_owner(user, vehicle) -> bool:
    if user is None or vehicle is None or _inactive(user):
        return False
    return vehicle.owner_id == user.id
