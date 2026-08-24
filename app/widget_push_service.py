import logging
from typing import Optional, TYPE_CHECKING

from app.database import SessionLocal
from app import crud

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


class BadgeService:
    """Manages push notification badge counts per vehicle."""

    def increment_badge_count(self, vehicle_id: str) -> Optional[int]:
        """Increment badge count for a vehicle. Returns new count, or None on failure."""
        db = SessionLocal()
        try:
            vehicle_db = crud.vehicle.get_vehicle_by_vehicle_id(db, vehicle_id)
            if not vehicle_db:
                logger.warning(f"Cannot increment badge count for unknown vehicle ID: {vehicle_id}")
                return None

            vehicle_db.badge_count += 1
            db.commit()
            new_count = vehicle_db.badge_count
            logger.debug(f"Incremented badge count for vehicle {vehicle_id} to {new_count}")
            return new_count

        except Exception as e:
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
        """Reset badge count for all vehicles owned by a user. Returns number of vehicles reset."""
        db = SessionLocal()
        try:
            from app.models.db import Vehicle

            user_vehicles = db.query(Vehicle).filter(Vehicle.owner_id == user_id).all()

            total_old_count = 0
            vehicles_reset = 0

            for vehicle in user_vehicles:
                if vehicle.badge_count > 0:
                    total_old_count += vehicle.badge_count
                    vehicle.badge_count = 0
                    vehicles_reset += 1

            db.commit()
            logger.info(f"Reset badge counts for {vehicles_reset} vehicles (total {total_old_count} badges) for user {user_id}")
            return vehicles_reset

        except Exception as e:
            logger.error(f"Error resetting badge counts for user {user_id}: {e}", exc_info=True)
            return 0
        finally:
            db.close()


# Global instance
widget_push_service = BadgeService()
