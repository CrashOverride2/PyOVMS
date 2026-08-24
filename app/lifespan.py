import asyncio
import logging
from contextlib import asynccontextmanager
import json
from fastapi.concurrency import run_in_threadpool

from app.database import SessionLocal
from app.config import settings
from app.bootstrap import (
    run_migrations,
    initialize_services,
)
from app.mqtt_metrics_subscriber import mqtt_metrics_subscriber
from app.mqtt_notification_subscriber import mqtt_notification_subscriber
from app.mqtt_interactive_client import mqtt_interactive_client
from app.connection_manager import manager as connection_manager
from app.tcp_server import shutdown_tcp_servers, start_tcp_server_main
from app.websocket_manager import manager as websocket_manager
from app.utils.vehicle_data_presenter import parse_stored_msgs_for_vehicle_info
from app.utils.vehicle_state_parser import parse_v2_messages_to_metrics_dict
from app.metrics_manager import metrics_manager
import datetime
from app import crud
from app.services.charge_logger.charge_manager import charge_manager
from app.security_manager import security_manager, set_notification_function
from app.notifications import send_admin_security_notification
from app import notifications
from app.services.vehicle_service import trigger_karto_vehicle_deletion
from app.services.mqtt_sync_worker import mqtt_sync_worker

module_logger = logging.getLogger(__name__)

SHUTDOWN_EVENT = asyncio.Event()
_running_tasks: list[asyncio.Task] = []


async def periodic_vehicle_data_broadcaster(shutdown_event: asyncio.Event):
    """Periodically gathers data for all vehicles with WebSocket subscribers and broadcasts it."""
    db = SessionLocal()
    try:
        while not shutdown_event.is_set():
            await asyncio.sleep(2)
            if not websocket_manager.subscriptions:
                continue

            vehicle_topics = [topic for topic in websocket_manager.subscriptions if topic.startswith("vehicle:")]
            if not vehicle_topics:
                continue
            
            try:
                db.expire_all()
            except Exception as e:
                # Same reasoning as the rollback below: this is the one statement in the
                # loop body outside the per-topic handler that can touch a broken session,
                # and letting it escape kills the broadcaster task for good.
                module_logger.error(f"Broadcaster could not expire its session: {e}", exc_info=True)
                try:
                    await run_in_threadpool(db.rollback)
                except Exception as rollback_error:
                    module_logger.error(f"Broadcaster session rollback failed: {rollback_error}", exc_info=True)
                continue

            for topic in vehicle_topics:
                try:
                    vehicle_id = topic.split(":", 1)[1]
                    vehicle_db = await run_in_threadpool(crud.vehicle.get_vehicle_by_vehicle_id, db, vehicle_id)
                    if not vehicle_db:
                        continue
                    
                    status_parsed, loc_parsed, tpms_parsed, diag_parsed = await run_in_threadpool(parse_stored_msgs_for_vehicle_info, vehicle_db)
                    
                    v2_metrics = await run_in_threadpool(parse_v2_messages_to_metrics_dict, vehicle_db)
                    v3_metrics = metrics_manager.get_metrics_for_vehicle(vehicle_id)

                    now_utc = datetime.datetime.now(datetime.timezone.utc)
                    is_v2_online = vehicle_id in connection_manager.car_connections
                    is_v3_online = False
                    if vehicle_db.last_seen_v3:
                        last_seen_v3_comp = vehicle_db.last_seen_v3.replace(tzinfo=datetime.timezone.utc) if vehicle_db.last_seen_v3.tzinfo is None else vehicle_db.last_seen_v3
                        if (now_utc - last_seen_v3_comp).total_seconds() < (15 * 60):
                            is_v3_online = True
                            
                    payload_to_send = {
                        "isV2Online": is_v2_online, "isV3Online": is_v3_online,
                        "soc": status_parsed.get('soc') if status_parsed else None,
                        "units": status_parsed.get('units') if status_parsed else None,
                        "line_voltage": status_parsed.get('line_voltage') if status_parsed else None,
                        "charge_current": status_parsed.get('charge_current') if status_parsed else None,
                        "charge_state_text": status_parsed.get('charge_state_text') if status_parsed else None,
                        "charge_mode_text": status_parsed.get('charge_mode_text') if status_parsed else None,
                        "estimated_range": status_parsed.get('estimated_range') if status_parsed else None,
                        "battery_voltage": status_parsed.get('battery_voltage') if status_parsed else None,
                        "battery_current": status_parsed.get('battery_current') if status_parsed else None,
                        "battery_soh": status_parsed.get('battery_soh') if status_parsed else None,
                        "vehicle_12v": diag_parsed.get('vehicle_12v') if diag_parsed else None,
                        "lat": loc_parsed.get('lat') if loc_parsed else None,
                        "lon": loc_parsed.get('lon') if loc_parsed else None,
                        "lastMessageAt": vehicle_db.last_message_at.isoformat() + "Z" if vehicle_db.last_message_at else None,
                        "tpms_data": tpms_parsed,
                        "v2_metrics": v2_metrics,
                        "v3_metrics": v3_metrics,
                    }
                    data_to_send = {"topic": topic, "type": "update", "payload": payload_to_send}
                    
                    module_logger.debug(f"WS OUT > {topic}: {json.dumps(data_to_send)[:200]}...")
                    
                    await websocket_manager.broadcast_to_topic(topic, data_to_send)
                except Exception as e:
                    module_logger.error(f"Error in broadcaster loop for topic {topic}: {e}", exc_info=True)
                    # Roll back before the next topic. This session lives for the whole
                    # process, so a failed statement leaves it in a failed transaction and
                    # every later iteration raises PendingRollbackError instead of the
                    # original error — the dashboard stops receiving live data until the
                    # server is restarted, and the log only shows the follow-on error.
                    try:
                        await run_in_threadpool(db.rollback)
                    except Exception as rollback_error:
                        module_logger.error(f"Broadcaster session rollback failed: {rollback_error}", exc_info=True)


    except asyncio.CancelledError:
        module_logger.info("Vehicle data broadcaster task cancelled.")
    except Exception as e:
        module_logger.error(f"Error in vehicle data broadcaster: {e}", exc_info=True)
    finally:
        db.close()
        module_logger.info("Vehicle data broadcaster task finished.")

async def periodic_housekeeping(shutdown_event: asyncio.Event):
    """Periodically cleans up old data from the database."""
    while not shutdown_event.is_set():
        try:
            for _ in range(3600):
                if shutdown_event.is_set(): break
                await asyncio.sleep(1)
            if shutdown_event.is_set(): break

            module_logger.info("Running periodic housekeeping...")
            metrics_manager.evict_stale_metrics()
            security_manager.sweep_stale_username_entries()
            db = SessionLocal()
            try:
                num_del_logs = crud.historical_data.delete_old_historical_data(db, older_than_days=settings.LOG_HISTORY_DAYS)
                if num_del_logs > 0:
                    module_logger.info(f"Housekeeping: Deleted {num_del_logs} old historical data entries.")
                
                num_exp_keys = crud.apikey.deactivate_and_remove_expired_api_keys_from_mqtt(db)
                if num_exp_keys > 0:
                    module_logger.info(f"Housekeeping: Deactivated {num_exp_keys} expired API keys.")
                
                crud.apikey.delete_expired_api_keys(db)

                await run_in_threadpool(charge_manager.check_for_stale_sessions, db)
            finally:
                db.close()
        except asyncio.CancelledError:
            break
    module_logger.info("Housekeeping task finished.")

async def periodic_lifecycle_housekeeping(shutdown_event: asyncio.Event):
    """Daily lifecycle management: warn/delete inactive vehicles and abandoned accounts."""
    while not shutdown_event.is_set():
        # Wait 24 hours between cycles (use 1-second sleeps so shutdown is responsive)
        for _ in range(86400):
            if shutdown_event.is_set():
                break
            await asyncio.sleep(1)
        if shutdown_event.is_set():
            break

        module_logger.info("Running lifecycle housekeeping...")
        db = SessionLocal()
        try:
            from app.models.db import User as UserModel
            admin_user = db.query(UserModel).filter(
                UserModel.is_admin == True,
                UserModel.is_active == True,
            ).first()

            # --- Step 1: Send warnings for vehicles inactive 365+ days ---
            vehicles_to_warn = crud.vehicle.get_vehicles_needing_unused_warning(db)
            for vehicle in vehicles_to_warn:
                owner = vehicle.owner
                if not owner:
                    continue
                last_seen = (
                    crud.vehicle._vehicle_last_seen(vehicle).strftime('%Y-%m-%d %H:%M UTC')
                    if crud.vehicle._vehicle_last_seen(vehicle) else "never"
                )
                try:
                    await asyncio.to_thread(
                        notifications.send_unused_vehicle_warning_email,
                        vehicle.vehicle_id, vehicle.vehicle_name, last_seen,
                        owner.email, owner.full_name or owner.username
                    )
                    await asyncio.to_thread(notifications.send_lifecycle_admin_notification, "unused_vehicle_warning", {
                        "vehicle_id": vehicle.vehicle_id,
                        "vehicle_name": vehicle.vehicle_name or "",
                        "last_seen": last_seen,
                        "owner_username": owner.username,
                        "owner_email": owner.email,
                        "user_management_url": f"{settings.SERVER_BASE_URL.rstrip('/')}/users",
                        "server_base_url": settings.SERVER_BASE_URL,
                    })
                    vehicle.unused_reminder_sent_at = datetime.datetime.now(datetime.timezone.utc)
                    db.commit()
                    module_logger.info(f"Lifecycle: Unused warning sent for vehicle {vehicle.vehicle_id} (owner: {owner.username})")
                except Exception as e:
                    module_logger.error(f"Lifecycle: Error warning for vehicle {vehicle.vehicle_id}: {e}", exc_info=True)

            # --- Step 2: Auto-delete vehicles warned 7+ days ago still inactive 365+ days ---
            vehicles_to_delete = crud.vehicle.get_vehicles_to_auto_delete(db)
            for vehicle in vehicles_to_delete:
                owner = vehicle.owner
                vehicle_id = vehicle.vehicle_id
                vehicle_name = vehicle.vehicle_name
                owner_email = owner.email if owner else None
                owner_username = owner.username if owner else "unknown"
                owner_display = (owner.full_name or owner.username) if owner else "unknown"
                vehicle_db_id = vehicle.id
                try:
                    car_conn = connection_manager.get_car_connection(vehicle_id)
                    if car_conn:
                        await car_conn.close()
                    if admin_user:
                        # Raises KartoDeletionFailed if the trip data could not be
                        # removed. The delete below is inside this try on purpose:
                        # the vehicle then survives and the next daily run retries,
                        # rather than leaving an orphaned GPS history behind.
                        await trigger_karto_vehicle_deletion(db, vehicle_id, admin_user)
                    crud.vehicle.delete_vehicle(db, vehicle_db_id)
                    if owner_email:
                        await asyncio.to_thread(notifications.send_vehicle_auto_deleted_email, vehicle_id, vehicle_name, owner_email, owner_display)
                    await asyncio.to_thread(notifications.send_lifecycle_admin_notification, "vehicle_auto_deleted", {
                        "vehicle_id": vehicle_id,
                        "vehicle_name": vehicle_name or "",
                        "owner_username": owner_username,
                        "owner_email": owner_email or "",
                        "user_management_url": f"{settings.SERVER_BASE_URL.rstrip('/')}/users",
                        "server_base_url": settings.SERVER_BASE_URL,
                    })
                    module_logger.info(f"Lifecycle: Auto-deleted inactive vehicle {vehicle_id} (owner: {owner_username})")
                except Exception as e:
                    module_logger.error(f"Lifecycle: Error auto-deleting vehicle {vehicle_id}: {e}", exc_info=True)

            # --- Step 3: Warn accounts with no vehicles and no login for 30+ days ---
            users_to_warn = crud.user.get_users_needing_deletion_warning(db)
            for user in users_to_warn:
                try:
                    await asyncio.to_thread(
                        notifications.send_account_deletion_warning_email,
                        user.email, user.full_name or user.username
                    )
                    await asyncio.to_thread(notifications.send_lifecycle_admin_notification, "account_deletion_warning", {
                        "username": user.username,
                        "email": user.email,
                        "user_management_url": f"{settings.SERVER_BASE_URL.rstrip('/')}/users",
                        "server_base_url": settings.SERVER_BASE_URL,
                    })
                    user.account_deletion_reminder_sent_at = datetime.datetime.now(datetime.timezone.utc)
                    db.commit()
                    module_logger.info(f"Lifecycle: Account deletion warning sent to {user.username}")
                except Exception as e:
                    module_logger.error(f"Lifecycle: Error warning account {user.username}: {e}", exc_info=True)

            # --- Step 4: Auto-delete accounts warned 7+ days ago still with no vehicles ---
            users_to_delete = crud.user.get_users_to_auto_delete(db)
            for user in users_to_delete:
                username = user.username
                email = user.email
                user_id = user.id
                try:
                    for vehicle in list(user.vehicles):
                        car_conn = connection_manager.get_car_connection(vehicle.vehicle_id)
                        if car_conn:
                            await car_conn.close()
                        if admin_user:
                            # Same as above: a failure here aborts the account
                            # deletion and it is retried on the next run.
                            await trigger_karto_vehicle_deletion(db, vehicle.vehicle_id, admin_user)
                    crud.user.delete_user(db, user_id)
                    await asyncio.to_thread(notifications.send_lifecycle_admin_notification, "account_auto_deleted", {
                        "username": username,
                        "email": email,
                        "user_management_url": f"{settings.SERVER_BASE_URL.rstrip('/')}/users",
                        "server_base_url": settings.SERVER_BASE_URL,
                    })
                    module_logger.info(f"Lifecycle: Auto-deleted inactive account {username}")
                except Exception as e:
                    module_logger.error(f"Lifecycle: Error auto-deleting account {username}: {e}", exc_info=True)

        except Exception as e:
            module_logger.error(f"Lifecycle housekeeping failed: {e}", exc_info=True)
        finally:
            db.close()

        module_logger.info("Lifecycle housekeeping complete.")


async def start_background_tasks(shutdown_event: asyncio.Event) -> list[asyncio.Task]:
    """Starts all long-running background tasks."""
    tasks = [
        asyncio.create_task(periodic_housekeeping(shutdown_event)),
        asyncio.create_task(periodic_vehicle_data_broadcaster(shutdown_event)),
        asyncio.create_task(periodic_lifecycle_housekeeping(shutdown_event)),
        asyncio.create_task(mqtt_sync_worker.run(shutdown_event)),
    ]
    server_tasks = await start_tcp_server_main()
    tasks.extend(server_tasks)
    return tasks


@asynccontextmanager
async def lifespan(app):
    global _running_tasks

    module_logger.info("Lifespan: Starting up PyOVMS Server...")
    SHUTDOWN_EVENT.clear()
    await run_migrations()
    await initialize_services()

    # Initialize security notification function
    set_notification_function(send_admin_security_notification)
    module_logger.info("Security notification system initialized")

    # Restore persisted IP blocks that survived a restart
    security_manager.load_from_db()
    module_logger.info("Rate-limiter state restored from database")

    _running_tasks = await start_background_tasks(SHUTDOWN_EVENT)

    module_logger.info("Application startup complete.")
    yield
    
    module_logger.info("Shutting down PyOVMS Server...")
    SHUTDOWN_EVENT.set()

    # Write out queued broker credential changes before the worker task is cancelled
    await mqtt_sync_worker.flush()

    # Producers first. Everything below can still hand a notification to the fan-out —
    # an MQTT message, a V2 'P' frame, the lifecycle housekeeping's mail — so shutting
    # the fan-out and the mail queue down ahead of them only means the work they produce
    # afterwards is silently dropped.
    mqtt_metrics_subscriber.disconnect()
    # Blocks while its two bounded pools drain (up to ~30 s), so it runs on a thread:
    # on the event loop it would stall every response still being written.
    await asyncio.to_thread(mqtt_notification_subscriber.disconnect)
    mqtt_interactive_client.disconnect()

    connection_manager.stop_idle_checker()
    await connection_manager.close_all_connections()

    await shutdown_tcp_servers()

    for task in _running_tasks:
        task.cancel()

    if _running_tasks:
        module_logger.info(f"Awaiting shutdown of {len(_running_tasks)} background tasks...")
        await asyncio.gather(*_running_tasks, return_exceptions=True)

    # Then the consumers, innermost last. Both calls block for as long as the in-flight
    # sends take, so they run on a thread: on the event loop they stall every response
    # the server has not finished writing yet.
    await asyncio.to_thread(notifications.shutdown_dispatch_pool)
    notifications.shutdown_apns_client()
    # The fan-out is a producer for the mail queue, so it drains first.
    await asyncio.to_thread(notifications.shutdown_email_queue)

    module_logger.info("PyOVMS Server shutdown complete.")