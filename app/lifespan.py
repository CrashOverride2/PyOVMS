import asyncio
import hashlib
import logging
import time
from contextlib import asynccontextmanager
import json
import msgpack
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
from app.websocket_manager import VEHICLE_TOPIC_PREFIX, manager as websocket_manager
from app.utils.vehicle_live_payload import build_vehicle_live_payload
from app.utils.timestamps import as_utc
from app.metrics_manager import metrics_manager
import datetime
from app import crud
from app.services.charge_logger.charge_manager import charge_manager
from app.security_manager import security_manager, set_notification_function
from app.security_events import security_event_logger, SecurityEventType
from app.notifications import send_admin_security_notification
from app import notifications
from app.services.vehicle_service import trigger_karto_vehicle_deletion
from app.services.mqtt_sync_worker import mqtt_sync_worker

module_logger = logging.getLogger(__name__)

SHUTDOWN_EVENT = asyncio.Event()
_running_tasks: list[asyncio.Task] = []


def _build_live_payloads(db, vehicle_ids: list[str]) -> dict[str, tuple[dict, bytes]]:
    """
    The live payload of every listed vehicle, with a digest of each — one threadpool
    hop for the whole tick instead of two per vehicle.

    Synchronous: runs on the threadpool. `expire_all()` first, because this session
    lives for the whole process and would otherwise hand back the vehicle rows it
    loaded on the previous tick. The digest is of the packed payload, so "unchanged"
    is decided by bytes and not by anything a metric could spoof.

    The query is outside the per-vehicle try and the parse inside it, on purpose. A
    database error is one failure for the tick and is answered by the caller's
    rollback; a stored message one vehicle's parser cannot digest is that vehicle's
    problem alone, and must not stop the frame of every other vehicle on the server
    — with one shared hop per tick, that is what an unguarded parse would do.
    """
    db.expire_all()
    out: dict[str, tuple[dict, bytes]] = {}
    # One SELECT for every watched vehicle, not one per vehicle: the parse below is
    # the cost that scales with the fleet, the round trips should not add to it.
    vehicles = crud.vehicle.get_vehicles_by_vehicle_ids(db, vehicle_ids)
    for vehicle_id in vehicle_ids:
        vehicle_db = vehicles.get(vehicle_id.upper())
        if not vehicle_db:
            continue
        try:
            payload = build_vehicle_live_payload(vehicle_db)
            digest = hashlib.blake2b(msgpack.packb(payload, use_bin_type=True), digest_size=16).digest()
        except Exception as e:
            module_logger.error(f"Broadcaster could not build the live payload of {vehicle_id}: {e}", exc_info=True)
            continue
        out[vehicle_id] = (payload, digest)
    return out


async def periodic_vehicle_data_broadcaster(shutdown_event: asyncio.Event):
    """
    Periodically gathers data for all vehicles with WebSocket subscribers and broadcasts it.

    The cost of a tick is per *topic*, not per tab: five tabs of the same dashboard
    subscribe to the same vehicles, and the query and parse happen once for all of
    them. What bounds a tick is therefore the number of vehicles on the server that
    anyone is watching — a fleet account's dashboard subscribes to every one of its
    vehicles — and three things keep that affordable:

    * one threadpool hop builds every payload of the tick (`_build_live_payloads`),
      instead of two hops per vehicle in sequence;
    * a topic is sent only when its payload changed, or a subscriber joined since it
      was last sent. A sleeping module produced the same frame for every tab every
      two seconds, and a dashboard of 90 vehicles was 90 packed sends per tick with
      nothing new in any of them. The new subscriber gets the current frame at once,
      so a tab that reconnects is not left with stale numbers until the vehicle
      moves;
    * a tick that overruns the interval is logged (rate limited): the failure mode
      of this loop is silent lag, and nothing else reports it.

    A client that stops reading is cut off by the send timeout in
    `broadcast_to_topic`, so it cannot hold the tick for everyone else.
    """
    db = SessionLocal()
    interval = settings.WS_BROADCAST_INTERVAL_SECONDS
    # topic -> (subscribers when last sent, digest last sent)
    last_sent: dict[str, tuple[frozenset, bytes]] = {}
    overrun_logged_at = 0.0
    try:
        while not shutdown_event.is_set():
            await asyncio.sleep(interval)
            if not websocket_manager.subscriptions:
                last_sent.clear()
                continue

            # Only vehicle topics carry live data; `user:` topics are event-driven.
            vehicle_topics = [
                topic for topic in websocket_manager.subscriptions if topic.startswith(VEHICLE_TOPIC_PREFIX)
            ]
            if not vehicle_topics:
                last_sent.clear()
                continue
            for topic in [t for t in last_sent if t not in websocket_manager.subscriptions]:
                del last_sent[topic]

            started = time.monotonic()
            try:
                vehicle_ids = [topic[len(VEHICLE_TOPIC_PREFIX):] for topic in vehicle_topics]
                built = await run_in_threadpool(_build_live_payloads, db, vehicle_ids)
            except Exception as e:
                module_logger.error(f"Broadcaster could not build the live payloads: {e}", exc_info=True)
                # Roll back before the next tick. This session lives for the whole
                # process, so a failed statement leaves it in a failed transaction and
                # every later iteration raises PendingRollbackError instead of the
                # original error — the dashboard stops receiving live data until the
                # server is restarted, and the log only shows the follow-on error.
                try:
                    await run_in_threadpool(db.rollback)
                except Exception as rollback_error:
                    module_logger.error(f"Broadcaster session rollback failed: {rollback_error}", exc_info=True)
                continue

            for topic in vehicle_topics:
                try:
                    entry = built.get(topic[len(VEHICLE_TOPIC_PREFIX):])
                    if entry is None:
                        continue
                    payload_to_send, digest = entry
                    subscribers = websocket_manager.subscribers_of(topic)
                    if not subscribers:
                        continue
                    if last_sent.get(topic) == (subscribers, digest):
                        continue
                    last_sent[topic] = (subscribers, digest)

                    data_to_send = {"topic": topic, "type": "update", "payload": payload_to_send}
                    if module_logger.isEnabledFor(logging.DEBUG):
                        module_logger.debug(f"WS OUT > {topic}: {json.dumps(data_to_send, default=str)[:200]}...")
                    await websocket_manager.broadcast_to_topic(topic, data_to_send)
                except Exception as e:
                    module_logger.error(f"Error in broadcaster loop for topic {topic}: {e}", exc_info=True)
                    # Nothing above touches the session, but the invariant is "every
                    # handler in this loop rolls back" (test_db_session_resilience), and
                    # a rollback on a clean session is free.
                    try:
                        await run_in_threadpool(db.rollback)
                    except Exception as rollback_error:
                        module_logger.error(f"Broadcaster session rollback failed: {rollback_error}", exc_info=True)

            elapsed = time.monotonic() - started
            if elapsed > interval and started - overrun_logged_at > 60:
                overrun_logged_at = started
                module_logger.warning(
                    f"Live-data tick took {elapsed:.1f}s for {len(vehicle_topics)} vehicle topic(s), "
                    f"over the {interval:.0f}s interval: dashboards are falling behind."
                )

    except asyncio.CancelledError:
        module_logger.info("Vehicle data broadcaster task cancelled.")
    except Exception as e:
        module_logger.error(f"Error in vehicle data broadcaster: {e}", exc_info=True)
    finally:
        db.close()
        module_logger.info("Vehicle data broadcaster task finished.")

def purge_expired_registrations(db) -> int:
    """
    Delete accounts whose e-mail verification link expired without being used.

    Runs hourly rather than in the daily lifecycle pass: the link is valid for
    EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS, and whoever mistyped their address wants
    the username back the same day, not after up to two of them. The deletion goes
    through crud.user.delete_user() like every other account removal and is recorded
    as USER_DELETED — with user_id=None, since the row is gone by then.
    """
    removed = 0
    for user in crud.user.get_users_with_expired_verification(db):
        username, email, user_id = user.username, user.email, user.id
        try:
            crud.user.delete_user(db, user_id)
        except Exception as e:
            module_logger.error(f"Housekeeping: Failed to delete unverified account '{username}': {e}", exc_info=True)
            db.rollback()
            continue
        removed += 1
        module_logger.info(f"Housekeeping: Deleted unverified account '{username}' ({email}); its verification link expired unused.")
        try:
            security_event_logger.log_event(
                db=db, event_type=SecurityEventType.USER_DELETED,
                user_id=None, username=username,
                details={"reason": "verification_expired", "deleted_user_id": user_id, "email": email},
            )
        except Exception as e:
            module_logger.warning(f"Housekeeping: Could not record deletion of '{username}': {e}")
    return removed


def _run_housekeeping_pass(db) -> None:
    """
    One hourly pass, synchronous: it runs on the threadpool.

    Every step here is a database round trip — the history purge is a DELETE over a
    table that grows by every `notify/data` record a fleet sends — and they used to
    run inline on the event loop, where a slow one stalled every socket and response
    of the worker for its duration. Each step is its own try: the pass that fails to
    purge history must still expire API keys and unverified accounts.
    """
    steps = (
        ("purge old historical data",
         lambda: crud.historical_data.delete_old_historical_data(db, older_than_days=settings.LOG_HISTORY_DAYS),
         "Housekeeping: Deleted {n} old historical data entries."),
        ("deactivate expired API keys",
         lambda: crud.apikey.deactivate_and_remove_expired_api_keys_from_mqtt(db),
         "Housekeeping: Deactivated {n} expired API keys."),
        ("delete expired API keys", lambda: crud.apikey.delete_expired_api_keys(db), None),
        ("purge unverified accounts", lambda: purge_expired_registrations(db),
         "Housekeeping: Deleted {n} account(s) with an expired verification link."),
        ("close stale charge sessions", lambda: charge_manager.check_for_stale_sessions(db), None),
    )
    for label, step, message in steps:
        try:
            count = step()
        except Exception as e:
            module_logger.error(f"Housekeeping: could not {label}: {e}", exc_info=True)
            # A failed statement leaves the session in a failed transaction; without
            # this every later step raises PendingRollbackError instead of running.
            try:
                db.rollback()
            except Exception as rollback_error:
                module_logger.error(f"Housekeeping: rollback failed: {rollback_error}", exc_info=True)
            continue
        if message and isinstance(count, int) and count > 0:
            module_logger.info(message.format(n=count))


async def periodic_housekeeping(shutdown_event: asyncio.Event):
    """
    Hourly cleanup: expired history, API keys, unverified accounts, stale charge sessions.

    The loop itself must survive anything a pass raises. It used to catch only
    CancelledError, so the first unexpected exception — a locked SQLite file, a
    dropped PostgreSQL connection — ended the task for the life of the process, and
    the only trace was "Task exception was never retrieved" at shutdown. Nothing
    expired and nothing was purged until the next restart.
    """
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
                await run_in_threadpool(_run_housekeeping_pass, db)
            finally:
                db.close()
        except asyncio.CancelledError:
            break
        except Exception as e:
            module_logger.error(f"Housekeeping pass failed: {e}", exc_info=True)
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
                    as_utc(crud.vehicle._vehicle_last_seen(vehicle)).strftime('%Y-%m-%d %H:%M UTC')
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
    # Before any producer exists: initialize_services() connects the MQTT subscribers,
    # whose dispatches reach the browser only through this loop.
    websocket_manager.bind_loop(asyncio.get_running_loop())
    try:
        await run_migrations()
        await initialize_services()

        # Initialize security notification function
        set_notification_function(send_admin_security_notification)
        module_logger.info("Security notification system initialized")

        # Restore persisted IP blocks that survived a restart
        security_manager.load_from_db()
        module_logger.info("Rate-limiter state restored from database")

        _running_tasks = await start_background_tasks(SHUTDOWN_EVENT)
    except BaseException:
        # A startup that fails never reaches the shutdown half below, and the loop it
        # bound is about to be closed by whoever started it.
        websocket_manager.unbind_loop()
        raise

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

    # Last: everything that could still hand the browser a notification has drained
    # above, and a loop reference must not outlive its lifespan — the test suite starts
    # several, and a bridge bound to a closed loop would only ever log a dropped send.
    websocket_manager.unbind_loop()

    module_logger.info("PyOVMS Server shutdown complete.")