"""
Support mode: an owner's time-limited grant of their vehicle to the admins.

While it runs, every admin reaches the vehicle's data as the owner does, and every
admin's API keys may read its MQTT subtree and write `client/` commands. Trips and
notification settings stay the owner's (see app/utils/vehicle_access.py).

Requests and the ACL generator check `support_active()` themselves;
`expire_due_grants()` (every minute) withdraws open subscriptions, rewrites the ACL
and files SUPPORT_MODE_EXPIRED. Every admin access is a throttled SUPPORT_ACCESS
security event; commands are never throttled.
"""

import contextvars
import datetime
import logging
import threading
import time
from typing import Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from app.models import db as models_db
from app.security_events import (
    SecurityEventType,
    log_support_mode_change,
    security_event_logger,
)
from app.services.mqtt_sync_worker import mqtt_sync_worker
from app.utils.command_summary import summarize_command  # noqa: F401  (the audit's, re-exported)
from app.utils.timestamps import as_utc
from app.utils.vehicle_access import VehicleAccess, support_active, vehicle_access
from app.websocket_manager import VEHICLE_TOPIC_PREFIX, manager as websocket_manager, vehicle_topic

logger = logging.getLogger(__name__)

# The durations an owner may choose. Keys are what the form posts; the labels are
# the template's.
SUPPORT_DURATIONS: Dict[str, datetime.timedelta] = {
    "24h": datetime.timedelta(hours=24),
    "7d": datetime.timedelta(days=7),
    "30d": datetime.timedelta(days=30),
}

# One SUPPORT_ACCESS row per (admin, vehicle, kind) per this many seconds.
ACCESS_LOG_INTERVAL_SECONDS = 15 * 60
# A command changes the vehicle; each one is recorded.
UNTHROTTLED_KINDS = frozenset({"command"})
_THROTTLE_MAX_ENTRIES = 10_000

# Switching support off and on again must not mail every admin each time.
ADMIN_MAIL_INTERVAL_SECONDS = 10 * 60


# The caller's address for the audit, set per request by SecurityMiddleware and per
# socket by the /ws handler.
client_ip_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("support_client_ip", default=None)

_throttle_lock = threading.Lock()
_last_logged: Dict[Tuple[int, str, str], float] = {}
_last_mailed: Dict[str, float] = {}


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _should_log(admin_id: int, vehicle_id: str, kind: str) -> bool:
    if kind in UNTHROTTLED_KINDS:
        return True
    key = (admin_id, vehicle_id, kind)
    now = time.monotonic()
    with _throttle_lock:
        last = _last_logged.get(key)
        if last is not None and now - last < ACCESS_LOG_INTERVAL_SECONDS:
            return False
        if len(_last_logged) >= _THROTTLE_MAX_ENTRIES:
            _last_logged.clear()
        _last_logged[key] = now
        return True


def _forget_vehicle(vehicle_id: str) -> None:
    """A new grant starts a fresh audit: its first access is recorded at once."""
    with _throttle_lock:
        for key in [k for k in _last_logged if k[1] == vehicle_id]:
            del _last_logged[key]


def reset_throttles() -> None:
    """For tests."""
    with _throttle_lock:
        _last_logged.clear()
        _last_mailed.clear()


def record_support_access(
    user,
    vehicle,
    kind: str,
    *,
    ip: Optional[str] = None,
    detail: Optional[dict] = None,
) -> None:
    """File a SUPPORT_ACCESS event for an admin's access under a grant. Never raises.

    Writes through a session of its own: `log_event` commits the session it is
    handed, and the caller's request session is none of its business — nor is a
    failed audit row a reason to fail the request.
    """
    try:
        admin_id, admin_name = user.id, user.username
        vehicle_id = vehicle.vehicle_id
        owner = getattr(vehicle, "owner", None)
        details = {
            "vehicle_id": vehicle_id,
            "owner_id": vehicle.owner_id,
            "owner_username": owner.username if owner is not None else None,
            "kind": kind,
        }
        until = as_utc(vehicle.support_until)
        if until is not None:
            details["support_until"] = until.isoformat()
        details.update(detail or {})
    except Exception:
        logger.exception("Could not describe a support access for the audit")
        return
    if not _should_log(admin_id, vehicle_id, kind):
        return
    ip = ip or client_ip_var.get()
    from app.database import SessionLocal

    db = SessionLocal()
    try:
        security_event_logger.log_event(
            db=db,
            event_type=SecurityEventType.SUPPORT_ACCESS,
            user_id=admin_id,
            username=admin_name,
            ip_address=ip,
            details=details,
        )
    except Exception:
        logger.exception("Failed to record support access of '%s' to %s", admin_name, vehicle_id)
        db.rollback()
        # The slot was taken for a row that was never written: freed, the next access
        # is recorded instead of a quarter hour going unaudited after one locked write.
        with _throttle_lock:
            _last_logged.pop((admin_id, vehicle_id, kind), None)
    finally:
        db.close()


def check_vehicle_access(
    user,
    vehicle,
    *,
    kind: str,
    ip: Optional[str] = None,
    detail: Optional[dict] = None,
) -> bool:
    """`can_access_vehicle()`, plus the audit when the access is an admin's under a grant.

    The call every data route makes. It may write (the audit), so an async route
    runs it through `run_in_threadpool`.
    """
    access = vehicle_access(user, vehicle)
    if access is VehicleAccess.SUPPORT:
        record_support_access(user, vehicle, kind, ip=ip, detail=detail)
    return access is not VehicleAccess.NONE


def enable_support(
    db: Session,
    vehicle: "models_db.Vehicle",
    owner: "models_db.User",
    duration_key: str,
    *,
    ip: Optional[str] = None,
    via: str = "ui",
) -> Tuple[datetime.datetime, bool]:
    """Open `vehicle` to the admins for the chosen duration; return (until, was_active).

    Enabling a running grant replaces its end, shorter or longer. Raises ValueError
    for a duration that is not offered, PermissionError for anyone but the owner.
    """
    duration = SUPPORT_DURATIONS.get(duration_key)
    if duration is None:
        raise ValueError(f"unknown support duration {duration_key!r}")
    if vehicle.owner_id != owner.id:
        raise PermissionError("only the owner may grant support access")
    now = _utcnow()
    was_active = support_active(vehicle, now)
    until = now + duration
    vehicle.support_until = until
    if not was_active:
        vehicle.support_enabled_at = now
    vehicle.support_granted_by_id = owner.id
    db.commit()
    if not was_active:
        _forget_vehicle(vehicle.vehicle_id)
    log_support_mode_change(
        db,
        change="enabled",
        vehicle_id=vehicle.vehicle_id,
        owner_id=owner.id,
        owner_username=owner.username,
        until=until,
        ip_address=ip,
        details={"duration": duration_key, "extended": was_active, "via": via},
    )
    mqtt_sync_worker.mark_acl_dirty()
    return until, was_active


def disable_support(
    db: Session,
    vehicle: "models_db.Vehicle",
    *,
    ip: Optional[str] = None,
    via: str = "ui",
) -> bool:
    """End the grant on `vehicle` now. Returns whether one was running."""
    was_active = support_active(vehicle)
    had_grant = vehicle.support_until is not None
    if not had_grant:
        return False
    owner = getattr(vehicle, "owner", None)
    vehicle.support_until = None
    vehicle.support_enabled_at = None
    vehicle.support_granted_by_id = None
    db.commit()
    log_support_mode_change(
        db,
        change="disabled" if was_active else "expired",
        vehicle_id=vehicle.vehicle_id,
        owner_id=vehicle.owner_id,
        owner_username=owner.username if owner is not None else None,
        ip_address=ip,
        details={"via": via},
    )
    withdraw_support(vehicle.vehicle_id, vehicle.owner_id)
    return was_active


def withdraw_support(vehicle_id: str, owner_id: int) -> None:
    """Take back from the admins what a running grant gave them outside a request.

    The ACL (their API keys' topics) and their open `vehicle:` subscriptions — the
    owner's own sockets are kept. Callable from any thread; never waits.
    """
    try:
        mqtt_sync_worker.mark_acl_dirty()
    except Exception:
        logger.exception("Could not queue the ACL rebuild after support on %s ended", vehicle_id)
    try:
        websocket_manager.withdraw_topic_from_others_threadsafe(vehicle_topic(vehicle_id), owner_id)
    except Exception:
        logger.exception("Could not withdraw the live topic of %s from the admins", vehicle_id)
    _forget_vehicle(vehicle_id)


def expire_due_grants(now: Optional[datetime.datetime] = None) -> List[str]:
    """Clear every grant past its end, file the event, withdraw it. Returns the vehicle ids.

    A session of its own, closed before it returns. The clear is conditional on the
    grant still being due, so an owner extending it at this very moment wins.
    """
    from app.database import SessionLocal

    now = as_utc(now) if now is not None else _utcnow()
    expired: List[str] = []
    db = SessionLocal()
    try:
        due = (
            db.query(models_db.Vehicle)
            .filter(
                models_db.Vehicle.support_until.isnot(None),
                models_db.Vehicle.support_until <= now,
            )
            .all()
        )
        for vehicle in due:
            vehicle_id, owner_id = vehicle.vehicle_id, vehicle.owner_id
            owner_name = vehicle.owner.username if vehicle.owner is not None else None
            until = as_utc(vehicle.support_until)
            try:
                cleared = (
                    db.query(models_db.Vehicle)
                    .filter(
                        models_db.Vehicle.id == vehicle.id,
                        models_db.Vehicle.support_until <= now,
                    )
                    .update(
                        {
                            models_db.Vehicle.support_until: None,
                            models_db.Vehicle.support_enabled_at: None,
                            models_db.Vehicle.support_granted_by_id: None,
                        },
                        synchronize_session=False,
                    )
                )
                db.commit()
            except Exception:
                db.rollback()
                logger.exception("Could not clear the expired support grant on %s", vehicle_id)
                continue
            if not cleared:
                continue
            log_support_mode_change(
                db,
                change="expired",
                vehicle_id=vehicle_id,
                owner_id=owner_id,
                owner_username=owner_name,
                until=until,
            )
            withdraw_support(vehicle_id, owner_id)
            expired.append(vehicle_id)
    finally:
        db.close()
    if expired:
        logger.info("Support mode expired for %d vehicle(s): %s", len(expired), ", ".join(expired))
    return expired


def withdraw_lapsed_subscriptions(now: Optional[datetime.datetime] = None) -> List[str]:
    """Take every `vehicle:` topic from the sockets of non-owners whose grant is not
    running; return the topics touched. Re-checked every pass, since a subscribe may
    complete after its grant ended. Any thread; never waits.
    """
    now = as_utc(now) if now is not None else _utcnow()
    try:
        held = {
            topic: {websocket_manager.connection_users.get(cid) for cid in list(cids)}
            for topic, cids in list(websocket_manager.subscriptions.items())
            if topic.startswith(VEHICLE_TOPIC_PREFIX)
        }
    except RuntimeError:
        # Changed under the snapshot on the event loop; the next pass reads it again.
        return []
    if not held:
        return []
    from app.crud import vehicle as vehicle_crud
    from app.database import SessionLocal

    db = SessionLocal()
    try:
        vehicles = vehicle_crud.get_vehicles_by_vehicle_ids(
            db, [topic[len(VEHICLE_TOPIC_PREFIX):] for topic in held]
        )
        lapsed = []
        for topic, users in held.items():
            vehicle = vehicles.get(topic[len(VEHICLE_TOPIC_PREFIX):].upper())
            # A vanished vehicle is delete_vehicle()'s to withdraw, from everyone.
            if vehicle is None or not (users - {vehicle.owner_id}) or support_active(vehicle, now):
                continue
            lapsed.append((topic, vehicle.owner_id))
    finally:
        db.close()
    for topic, owner_id in lapsed:
        try:
            websocket_manager.withdraw_topic_from_others_threadsafe(topic, owner_id)
        except Exception:
            logger.exception("Could not withdraw the lapsed topic %s", topic)
    if lapsed:
        logger.warning("Withdrew %d live topic(s) held without a running support grant: %s",
                       len(lapsed), ", ".join(t for t, _ in lapsed))
    return [t for t, _ in lapsed]


def get_active_support_vehicles(db: Session, now: Optional[datetime.datetime] = None) -> Dict[int, datetime.datetime]:
    """Vehicle row id → end of its running grant, for the admin dashboard."""
    now = as_utc(now) if now is not None else _utcnow()
    rows = (
        db.query(models_db.Vehicle)
        .filter(models_db.Vehicle.support_until.isnot(None), models_db.Vehicle.support_until > now)
        .all()
    )
    return {v.id: as_utc(v.support_until) for v in rows if support_active(v, now)}


def admin_mail_due(vehicle_id: str) -> bool:
    """Whether enabling support on `vehicle_id` should mail the admins now.

    Once per ADMIN_MAIL_INTERVAL_SECONDS per vehicle: switching it off and on
    again in a minute is one event to the admins, not five.
    """
    now = time.monotonic()
    with _throttle_lock:
        last = _last_mailed.get(vehicle_id)
        if last is not None and now - last < ADMIN_MAIL_INTERVAL_SECONDS:
            return False
        if len(_last_mailed) >= _THROTTLE_MAX_ENTRIES:
            _last_mailed.clear()
        _last_mailed[vehicle_id] = now
        return True
