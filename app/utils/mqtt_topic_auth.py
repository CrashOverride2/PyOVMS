"""
Ownership check for inbound MQTT topics.

OVMS topics are `ovms/{owner_username}/{VEHICLE_ID}/...`. Both backend subscribers
used to take the vehicle from the third segment and ignore the second one entirely,
verifying only that the vehicle existed. That is not enough: the Mosquitto ACL only
constrains the *prefix* an account may publish under, and every API key gets an
account with `topic readwrite ovms/{its-owner}/#`. Publishing to
`ovms/<my-username>/<someone-elses-vehicle>/metric/...` is therefore permitted by the
broker, and the server would happily attribute the data to the other user's car —
metrics, GPS position, charge state, historical records and push notifications alike.

Binding the vehicle to the owner named in the topic is what closes that gap. Keep the
check here rather than in each subscriber so both paths cannot drift apart.
"""

import logging
import time
from typing import Optional

from sqlalchemy.orm import Session

from app import crud

logger = logging.getLogger(__name__)

# Ownership rarely changes, but it must not be cached forever: a vehicle reassigned by
# an admin has to start working for its new owner without a restart. Negative results
# are cached too, otherwise every message naming an unknown vehicle costs a DB query.
_CACHE_TTL_SECONDS = 300
_CACHE_MAX_ENTRIES = 10_000

# vehicle_id -> (owner_username or None, monotonic timestamp)
_owner_cache: dict[str, tuple[Optional[str], float]] = {}


def clear_cache() -> None:
    """Drop the memoised ownership map (used by tests and on vehicle CRUD changes)."""
    _owner_cache.clear()


def resolve_owner(db_factory, vehicle_id: str) -> Optional[str]:
    """Return the owning username for `vehicle_id`, or None if unknown/ownerless."""
    now = time.monotonic()
    cached = _owner_cache.get(vehicle_id)
    if cached is not None and now - cached[1] < _CACHE_TTL_SECONDS:
        return cached[0]

    db: Session = db_factory()
    try:
        vehicle_db = crud.vehicle.get_vehicle_by_vehicle_id(db, vehicle_id)
        owner = vehicle_db.owner.username if vehicle_db and vehicle_db.owner else None
    finally:
        db.close()

    # Bound the cache: vehicle IDs come straight off the wire, so an attacker naming
    # random IDs must not be able to grow this dict without limit.
    if len(_owner_cache) >= _CACHE_MAX_ENTRIES:
        _owner_cache.clear()
    _owner_cache[vehicle_id] = (owner, now)
    return owner


def topic_owner_matches(db_factory, topic_username: str, vehicle_id: str) -> bool:
    """
    True if `vehicle_id` exists and is owned by `topic_username`.

    Comparison is case-sensitive on the username because usernames are stored and
    validated verbatim (`^[a-zA-Z0-9_-]+$`); the vehicle id is expected upper-cased by
    the caller, matching how it is persisted.
    """
    owner = resolve_owner(db_factory, vehicle_id)
    if owner is None:
        logger.debug("MQTT: dropping message for unknown or ownerless vehicle '%s'", vehicle_id)
        return False
    if owner != topic_username:
        logger.warning(
            "MQTT: rejected cross-tenant publish — topic claims owner '%s' but vehicle "
            "'%s' belongs to '%s'. Dropping.",
            topic_username, vehicle_id, owner,
        )
        return False
    return True
