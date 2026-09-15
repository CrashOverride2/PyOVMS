"""
CRUD entry point. Access is by submodule: `crud.vehicle.get_vehicle_by_vehicle_id(db, id)`.

This was six `from .x import *` lines. They worked — importing a submodule binds it on the
package, so `crud.vehicle` resolved as a side effect of the star import rather than
because anything asked for it — but they also re-exported 110 names nobody used, among
them `crud.json`, `crud.datetime`, `crud.hashlib`, `crud.secrets` and `crud.security`:
every import of every submodule, promoted to public API by accident.

Verified before the change: no call site in app/ or tests/ uses a flat `crud.<function>`,
and nothing reaches the package through getattr, so the submodules below are the complete
public surface. (`crud.check_vehicle_ownership` in app/services/charge_logger/api.py is a
different module — that package has its own crud.)
"""

from . import (
    apikey,
    autoprovision,
    command_favorite,
    config_backup,
    historical_data,
    push_subscription,
    system_setting,
    user,
    vehicle,
)

__all__ = [
    "apikey",
    "autoprovision",
    "command_favorite",
    "config_backup",
    "historical_data",
    "push_subscription",
    "system_setting",
    "user",
    "vehicle",
]
