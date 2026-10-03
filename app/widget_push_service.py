import logging
from typing import Optional, TYPE_CHECKING

from app.database import SessionLocal
from app import crud

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class BadgeService:
    """Push notification badge counts.

    Stored per vehicle (`Vehicle.badge_count`), *sent* per account: the app has one
    icon badge for every car, so a push carries the sum over all of the owner's
    vehicles. A per-vehicle figure on the icon dropped every other car's unread count
    the moment one of them sent something. The app clears the lot with
    `reset_all_badge_counts_for_user`.
    """

    def increment_badge_count(self, vehicle_id: str) -> Optional[int]:
        """Count one notification for a vehicle. Returns the owner's new total over all
        of their vehicles, or None on failure.

        The increment is a single UPDATE: notifications are dispatched from a pool, and
        a read-modify-write through the ORM lost a count whenever two for the same
        vehicle overlapped.
        """
        db = SessionLocal()
        try:
            from sqlalchemy import func
            from app.models.db import Vehicle

            vid = vehicle_id.upper()
            owner_id = db.query(Vehicle.owner_id).filter(Vehicle.vehicle_id == vid).scalar()
            if owner_id is None:
                logger.warning(f"Cannot increment badge count for unknown vehicle ID: {vehicle_id}")
                return None

            db.query(Vehicle).filter(Vehicle.vehicle_id == vid).update(
                {Vehicle.badge_count: Vehicle.badge_count + 1}, synchronize_session=False
            )
            db.commit()

            total = db.query(func.coalesce(func.sum(Vehicle.badge_count), 0)).filter(
                Vehicle.owner_id == owner_id
            ).scalar()
            total = int(total or 0)
            logger.debug(f"Incremented badge count for vehicle {vehicle_id}; account total {total}")
            return total

        except Exception as e:
            db.rollback()
            logger.error(f"Error incrementing badge count for vehicle {vehicle_id}: {e}", exc_info=True)
            return None
        finally:
            db.close()

    def reset_badge_count(self, vehicle_id: str) -> bool:
        """Reset badge count for a single vehicle."""
        db = SessionLocal()
        try:
            vehicle_db = crud.vehicle.get_vehicle_by_vehicle_id(db, vehicle_id)
            if not vehicle_db:
                logger.warning(f"Cannot reset badge count for unknown vehicle ID: {vehicle_id}")
                return False

            old_count = vehicle_db.badge_count
            vehicle_db.badge_count = 0
            db.commit()
            logger.info(f"Reset badge count for vehicle {vehicle_id} from {old_count} to 0")
            return True

        except Exception as e:
            logger.error(f"Error resetting badge count for vehicle {vehicle_id}: {e}", exc_info=True)
            return False
        finally:
            db.close()

    def reset_all_badge_counts_for_user(self, user_id: int) -> int:
        """Reset badge count for all vehicles owned by a user. Returns the number of
        vehicles whose count was above 0 — 0 means there was nothing to clear, and the
        other devices need not be told.

        One UPDATE: a count added between a read and the write would otherwise be
        zeroed without ever having been reported as cleared.
        """
        db = SessionLocal()
        try:
            from app.models.db import Vehicle

            vehicles_reset = (
                db.query(Vehicle)
                .filter(Vehicle.owner_id == user_id, Vehicle.badge_count > 0)
                .update({Vehicle.badge_count: 0}, synchronize_session=False)
            )
            db.commit()
            if vehicles_reset:
                logger.info(f"Reset badge counts for {vehicles_reset} vehicles for user {user_id}")
            return vehicles_reset

        except Exception as e:
            db.rollback()
            logger.error(f"Error resetting badge counts for user {user_id}: {e}", exc_info=True)
            return 0
        finally:
            db.close()


# Global instance
widget_push_service = BadgeService()
