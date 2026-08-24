#!/usr/bin/env python3
"""
Test script for sending widget push notifications directly.
Usage: python test_widget_push.py <vehicle_id> [--force] [--with-badge]
"""

import sys
import os

# Add the parent directory to the path so we can import app modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import argparse
from app.widget_push_service import widget_push_service
from app.database import SessionLocal
from app import crud
import logging

# Set up logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def inject_test_metrics(vehicle_id: str, soc: float = 75.0, range_est: float = 250.0,
                        is_charging: bool = False, battery_temp: float = 22.0,
                        charge_power: float = 0.0, speed: float = 0.0, vehicle_on: bool = False):
    """Inject test metrics into the metrics_manager for testing purposes."""
    from app.metrics_manager import metrics_manager
    import time

    test_metrics = {
        "v.b.soc": soc,
        "v.b.range.est": range_est,
        "v.c.charging": "yes" if is_charging else "no",
        "v.b.temp": battery_temp,
        "v.c.power": charge_power,
        "v.p.speed": speed,
        "v.e.on": "yes" if vehicle_on else "no",
    }

    # If charging, add some charging-specific metrics
    if is_charging:
        test_metrics["v.c.duration.full"] = 45  # 45 minutes to full
        test_metrics["v.c.current"] = 16.0  # 16A
        test_metrics["v.c.voltage"] = 230.0  # 230V
        test_metrics["v.c.limit.soc"] = 100  # Charge to 100%
        test_metrics["v.c.duration.soc"] = 30  # 30 minutes to target SOC

    logger.info(f"Injecting test metrics for vehicle {vehicle_id}:")
    for key, value in test_metrics.items():
        logger.info(f"  {key}: {value}")

    # Store metrics with current timestamp
    metrics_manager.store_metrics(vehicle_id, test_metrics, int(time.time()))
    logger.info("✅ Test metrics injected successfully")


def test_widget_push(vehicle_id: str, force_update: bool = False, include_badge: bool = False,
                     test_data: dict = None):
    """Test sending a widget push notification to a vehicle."""

    db = SessionLocal()
    try:
        # Get vehicle info
        vehicle_db = crud.vehicle.get_vehicle_by_vehicle_id(db, vehicle_id)
        if not vehicle_db:
            logger.error(f"Vehicle '{vehicle_id}' not found in database")
            return False

        logger.info(f"Found vehicle: {vehicle_id}")
        logger.info(f"  - Owner: {vehicle_db.owner.username if vehicle_db.owner else 'Unknown'}")
        logger.info(f"  - Silent push enabled: {vehicle_db.enable_silent_push_notifications}")
        logger.info(f"  - FCM token: {'Yes' if vehicle_db.fcm_token else 'No'}")
        logger.info(f"  - APNs token: {'Yes' if vehicle_db.apns_token else 'No'}")
        logger.info(f"  - FCM enabled: {vehicle_db.enable_fcm_notifications}")
        logger.info(f"  - APNs enabled: {vehicle_db.enable_apns_notifications}")
        logger.info(f"  - Current badge count: {vehicle_db.badge_count}")

        if not vehicle_db.enable_silent_push_notifications:
            logger.warning("Silent push notifications are disabled for this vehicle!")
            response = input("Continue anyway? (y/n): ")
            if response.lower() != 'y':
                return False

        # Inject test metrics if provided
        if test_data:
            logger.info("\n" + "="*60)
            inject_test_metrics(vehicle_id, **test_data)
            logger.info("="*60 + "\n")

        # Increment badge count if requested
        if include_badge:
            logger.info("Incrementing badge count...")
            widget_push_service.increment_badge_count(vehicle_id)
            db.refresh(vehicle_db)
            logger.info(f"New badge count: {vehicle_db.badge_count}")

        # Send widget update
        logger.info("\nSending widget update:")
        logger.info(f"  - force_update: {force_update}")
        logger.info(f"  - include_badge: {include_badge}")

        success = widget_push_service.send_widget_update(
            vehicle_id=vehicle_id,
            force_update=force_update,
            include_badge=include_badge
        )

        if success:
            logger.info("✅ Widget push sent successfully!")
            return True
        else:
            logger.error("❌ Failed to send widget push")
            return False

    except Exception as e:
        logger.error(f"Error testing widget push: {e}", exc_info=True)
        return False
    finally:
        db.close()


def list_vehicles():
    """List all vehicles in the database."""
    db = SessionLocal()
    try:
        from app.models.db import Vehicle
        vehicles = db.query(Vehicle).all()

        if not vehicles:
            logger.info("No vehicles found in database")
            return

        logger.info(f"\nFound {len(vehicles)} vehicle(s):")
        logger.info("-" * 80)

        for vehicle in vehicles:
            logger.info(f"Vehicle ID: {vehicle.vehicle_id}")
            logger.info(f"  Owner: {vehicle.owner.username if vehicle.owner else 'Unknown'}")
            logger.info(f"  Silent push: {'✅' if vehicle.enable_silent_push_notifications else '❌'}")
            logger.info(f"  FCM token: {'✅' if vehicle.fcm_token else '❌'}")
            logger.info(f"  APNs token: {'✅' if vehicle.apns_token else '❌'}")
            logger.info(f"  Badge count: {vehicle.badge_count}")
            logger.info("-" * 80)

    except Exception as e:
        logger.error(f"Error listing vehicles: {e}", exc_info=True)
    finally:
        db.close()


def reset_badge(vehicle_id: str):
    """Reset badge count for a vehicle."""
    success = widget_push_service.reset_badge_count(vehicle_id)
    if success:
        logger.info(f"✅ Badge count reset for vehicle {vehicle_id}")
    else:
        logger.error(f"❌ Failed to reset badge count for vehicle {vehicle_id}")
    return success


def main():
    parser = argparse.ArgumentParser(
        description='Test widget push notifications',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Send silent widget-only update (no badge change)
  python test_widget_push.py TESTCAR

  # Send widget update with badge count (simulates real notification)
  python test_widget_push.py TESTCAR --with-badge

  # Force update (bypass rate limiting and change detection)
  python test_widget_push.py TESTCAR --force

  # Use test data with custom SOC
  python test_widget_push.py TESTCAR --test-data --soc 85.5

  # Use test data with charging state
  python test_widget_push.py TESTCAR --test-data --soc 45 --charging --charge-power 7.2

  # Use test data while driving
  python test_widget_push.py TESTCAR --test-data --soc 60 --vehicle-on --speed 65

  # List all vehicles
  python test_widget_push.py --list

  # Reset badge count for a vehicle
  python test_widget_push.py TESTCAR --reset-badge
        """
    )

    parser.add_argument('vehicle_id', nargs='?', help='Vehicle ID to send test push to')
    parser.add_argument('--force', action='store_true',
                       help='Force update (bypass rate limiting and change detection)')
    parser.add_argument('--with-badge', action='store_true',
                       help='Include badge count (simulates real notification)')
    parser.add_argument('--list', action='store_true',
                       help='List all vehicles in the database')
    parser.add_argument('--reset-badge', action='store_true',
                       help='Reset badge count for the vehicle')

    # Test data options
    parser.add_argument('--test-data', action='store_true',
                       help='Inject test metrics for testing (required for other test data options)')
    parser.add_argument('--soc', type=float, default=75.0,
                       help='State of Charge percentage (default: 75.0)')
    parser.add_argument('--range', type=float, default=250.0, dest='range_est',
                       help='Estimated range in km (default: 250.0)')
    parser.add_argument('--battery-temp', type=float, default=22.0,
                       help='Battery temperature in °C (default: 22.0)')
    parser.add_argument('--charging', action='store_true',
                       help='Set vehicle as charging')
    parser.add_argument('--charge-power', type=float, default=0.0,
                       help='Charge power in kW (default: 0.0)')
    parser.add_argument('--vehicle-on', action='store_true',
                       help='Set vehicle as powered on')
    parser.add_argument('--speed', type=float, default=0.0,
                       help='Vehicle speed in km/h (default: 0.0)')

    args = parser.parse_args()

    # List vehicles
    if args.list:
        list_vehicles()
        return

    # Check if vehicle_id is provided for other operations
    if not args.vehicle_id:
        parser.print_help()
        print("\nError: vehicle_id is required unless using --list")
        sys.exit(1)

    # Reset badge
    if args.reset_badge:
        reset_badge(args.vehicle_id)
        return

    # Prepare test data if requested
    test_data = None
    if args.test_data:
        test_data = {
            'soc': args.soc,
            'range_est': args.range_est,
            'battery_temp': args.battery_temp,
            'is_charging': args.charging,
            'charge_power': args.charge_power,
            'vehicle_on': args.vehicle_on,
            'speed': args.speed,
        }

    # Send widget push
    success = test_widget_push(
        vehicle_id=args.vehicle_id,
        force_update=args.force,
        include_badge=args.with_badge,
        test_data=test_data
    )

    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
