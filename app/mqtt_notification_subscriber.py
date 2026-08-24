import paho.mqtt.client as mqtt
import logging
import threading
import time
import datetime
import hashlib
from sqlalchemy.orm import sessionmaker
from typing import Dict, Tuple

from app.config import settings
from app import notifications, crud
from app.database import engine
from app.utils.bounded_worker import BoundedWorkerPool, OverflowPolicy
from app.utils.data_record_blocklist import get_record_blocklist
from app.utils import mqtt_topic_auth

logger = logging.getLogger(__name__)

class MqttNotificationSubscriber:
    """Listens to the MQTT broker for vehicle notifications and dispatches them."""

    DUPLICATE_NOTIFICATION_WINDOW_SECONDS = 10.0  # Increased to 10s to match notification rate limit
    SIMILAR_NOTIFICATION_WINDOW_SECONDS = 10.0  # Group similar notification types (e.g., TPMS warnings)

    # Hard ceiling for the de-duplication caches. Only the type cache can really grow
    # — its key carries the notification subtype, which is whatever the publisher put
    # in the topic — so an owner (or a compromised module) publishing
    # `.../notify/info/1`, `/2`, `/3`, … added a permanent entry per message. Neither
    # cache had a TTL, a cap or eviction, and the 10-second windows only suppress
    # *sending*, never *caching*. The result was steady heap growth until OOM, which
    # takes down every tenant at once.
    MAX_CACHE_ENTRIES = 10_000

    def __init__(self):
        self._client: mqtt.Client = None
        self._SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        self._last_notification_cache: Dict[str, Tuple[float, str]] = {}  # vehicle_id -> (time, message_hash)
        self._last_notification_type_cache: Dict[str, Tuple[float, str]] = {}  # vehicle_id -> (time, notification_type)
        # The caches are written from the paho thread and cleared from a dispatch worker
        # (see _forget_dedup), so they are no longer single-threaded.
        self._cache_lock = threading.Lock()

        # Push notifications. Drops the *oldest* when saturated: the queue only backs up
        # when sends are failing, and at that point the freshest alert is the one worth
        # keeping — an hour-old "charge complete" is worse than nothing.
        self._dispatch_pool = BoundedWorkerPool(
            name="ovms-notify",
            workers=settings.NOTIFY_DISPATCH_WORKERS,
            maxsize=settings.NOTIFY_DISPATCH_QUEUE_SIZE,
            overflow=OverflowPolicy.DROP_OLDEST,
        )

        # History records. One worker, because records for a vehicle have to be stored in
        # the order they arrived, and back-pressure rather than dropping, because these
        # are data — the broker's flow control is the right place for the queue to form,
        # not our heap.
        self._data_pool = BoundedWorkerPool(
            name="ovms-notify-data",
            workers=1,
            maxsize=settings.NOTIFY_DATA_QUEUE_SIZE,
            overflow=OverflowPolicy.BLOCK,
            block_timeout=30.0,
        )

    def _dispatch_safely(self, **kwargs) -> None:
        """
        Run the dispatch and swallow failures.

        A worker thread that raises loses the exception silently, and a notification
        that cannot be delivered must never look like a delivered one in the log.
        """
        vehicle_id = kwargs.get("vehicle_id")
        try:
            considered = notifications.dispatch_notification_to_vehicle(**kwargs)
        except Exception as e:
            logger.error(
                f"Notification dispatch failed for vehicle "
                f"'{vehicle_id}': {e}", exc_info=True
            )
            return

        if considered is False:
            # The dispatcher's rate limiter threw the message away, so nothing was
            # delivered — but the de-duplication entry recorded on the way in is still
            # sitting there, and would suppress the *next* copy of this message as a
            # duplicate of one that never went anywhere. Two independent suppressors in
            # series otherwise silently multiply into a much longer blackout than either
            # of them describes.
            self._forget_dedup(vehicle_id)

    def _forget_dedup(self, vehicle_id: str) -> None:
        """Release the de-duplication slot held for a message that was never sent."""
        if not vehicle_id:
            return
        with self._cache_lock:
            self._last_notification_cache.pop(vehicle_id, None)

    def _prune_caches(self, now: float) -> None:
        """
        Drop entries that have fallen out of their suppression window.

        Correct by construction rather than by tuning: an entry older than its window
        can no longer suppress anything, so removing it cannot change a decision. The
        cap is the backstop for a burst inside a single window, where every entry is
        still live — it clears rather than evicting one by one, which at worst costs
        a few duplicate notifications instead of unbounded memory.

        Caller holds `_cache_lock`.
        """
        for cache, window in (
            (self._last_notification_cache, self.DUPLICATE_NOTIFICATION_WINDOW_SECONDS),
            (self._last_notification_type_cache, self.SIMILAR_NOTIFICATION_WINDOW_SECONDS),
        ):
            stale = [key for key, (seen_at, _) in cache.items() if now - seen_at > window]
            for key in stale:
                del cache[key]
            if len(cache) > self.MAX_CACHE_ENTRIES:
                logger.warning(
                    f"Notification de-duplication cache exceeded {self.MAX_CACHE_ENTRIES} "
                    f"live entries; clearing it."
                )
                cache.clear()

    def connect(self, username: str, password: str):
        if not settings.MQTT_BROKER_HOST:
            logger.warning("MQTT Notification Subscriber disabled: Broker host not configured.")
            return

        # clean_session=False: the broker keeps the session so the QoS 2 'data' records
        # below get queued while this service is down. The push-relevant types stay on
        # QoS 0 subscriptions, which are never queued - a reboot can therefore neither
        # duplicate nor belatedly deliver push notifications.
        self._client = mqtt.Client(client_id="pyovms_notification_subscriber", clean_session=False)
        self._client.username_pw_set(username, password)

        self._client.on_connect = self._on_connect
        self._client.on_message = self._on_message

        try:
            self._client.connect(settings.MQTT_BROKER_HOST, settings.MQTT_BROKER_PORT, 60)
            self._client.loop_start()
        except Exception as e:
            logger.error(f"MQTT Notification Subscriber failed to connect: {e}", exc_info=True)

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            logger.info("MQTT Notification Subscriber connected to broker.")
            # Per-type subscriptions instead of notify/# so the QoS levels don't overlap
            # (overlapping subscriptions may cause duplicate deliveries on some brokers):
            # - push types at QoS 0: live only, never queued by the broker -> a reboot
            #   cannot replay or duplicate push notifications
            # - data records at QoS 2: exactly-once, queued across our restarts thanks to
            #   the persistent session
            # 'stream' is intentionally not subscribed (was dropped unprocessed before).
            # NOTE: the session persists on the broker - if a subscription is removed
            # here, add an explicit unsubscribe for it.
            topics = [
                ("ovms/+/+/notify/info/#", 0),
                ("ovms/+/+/notify/alert/#", 0),
                ("ovms/+/+/notify/warn/#", 0),
                ("ovms/+/+/notify/error/#", 0),
                ("ovms/+/+/notify/data/#", 2),
            ]
            client.unsubscribe("ovms/+/+/notify/#")  # drop the legacy catch-all if persisted
            client.subscribe(topics)
            logger.info(f"Subscribed to MQTT notification topics: {[t for t, q in topics]}")
        else:
            logger.error(f"MQTT Notification Subscriber connection failed with code {rc}")

    def _on_message(self, client, userdata, msg):
        try:
            parts = msg.topic.split('/')
            if len(parts) < 5 or parts[3] != 'notify':
                return

            topic_username = parts[1]
            vehicle_id = parts[2]
            notification_type = parts[4]

            # Same reason as in the metrics subscriber: the broker ACL only pins the
            # topic prefix to the publishing account, so without this check any user
            # could push arbitrary alerts to another owner's devices and write
            # historical records into their vehicle.
            if not mqtt_topic_auth.topic_owner_matches(self._SessionLocal, topic_username, vehicle_id.upper()):
                return

            # 'data' notifications carry historical CSV records, never push notifications.
            # We track charge sessions and trips via our own services; debug records are saved to DB.
            #
            # The storing runs on `_data_pool`, not here.
            #
            # paho has exactly one network thread and calls this back synchronously, so
            # for as long as this function runs nothing else is read from the socket.
            # Storing a record inline meant a session, two or three queries, an INSERT
            # and a COMMIT on that thread — per record — and the push notifications
            # arriving behind them waited for all of it. A module that has been asleep
            # flushes its whole history buffer on reconnect, which is exactly the moment
            # it also sends the alert somebody is waiting for; on a server with a fleet
            # on it the alert came out hours late. Parsing stays here (it is cheap, and
            # a malformed topic should be reported by the thread that saw it); only the
            # database work is handed over.
            if notification_type == 'data':
                subtype_category = parts[5] if len(parts) > 5 else None
                if subtype_category == 'debug' and len(parts) >= 8:
                    debug_name = parts[6] if len(parts) > 6 else 'unknown'
                    try:
                        record_number = int(parts[7])
                        timediff_seconds = int(parts[8]) if len(parts) > 8 else 0
                        message_plain = msg.payload.decode().strip()
                    except (ValueError, IndexError, UnicodeDecodeError) as e:
                        logger.error(f"Error parsing V3 debug data topic {msg.topic}: {e}")
                        return
                    if debug_name == 'crash':
                        self._data_pool.submit(
                            self._handle_v3_crash_log,
                            vehicle_id, record_number, timediff_seconds, message_plain,
                        )
                    else:
                        self._data_pool.submit(
                            self._handle_v3_debug_data,
                            vehicle_id, debug_name, record_number, timediff_seconds, message_plain,
                        )
                else:
                    # Generic history record: store it in the historical_data table so the
                    # vehicle detail page can present it (unless its type is blocklisted or
                    # a dedicated service consumes it, e.g. the GPS logs handled by Karto).
                    self._data_pool.submit(
                        self._handle_v3_data_record,
                        vehicle_id, list(parts), msg.payload.decode(errors='replace').strip(),
                    )
                return

            # 'stream' notifications are high-frequency live data, not suitable for push.
            if notification_type == 'stream':
                logger.debug(f"MQTT Notify: Dropping 'stream' notification for '{vehicle_id}'.")
                return

            # info / alert / warn / error → push dispatch
            message_plain = msg.payload.decode().strip()
            subtype = "/".join(parts[5:]) if len(parts) > 5 else "general"

            now = time.time()
            notification_key = f"{notification_type}/{subtype}"
            cache_key = f"{vehicle_id}:{notification_key}"
            message_hash = hashlib.sha1(message_plain.encode()).hexdigest()

            with self._cache_lock:
                self._prune_caches(now)

                # Check 1: Exact duplicate detection (same message content)
                if vehicle_id in self._last_notification_cache:
                    last_time, last_hash = self._last_notification_cache[vehicle_id]
                    if (now - last_time < self.DUPLICATE_NOTIFICATION_WINDOW_SECONDS) and (last_hash == message_hash):
                        logger.debug(f"MQTT Notify: Suppressing exact duplicate notification for vehicle '{vehicle_id}'.")
                        return
                self._last_notification_cache[vehicle_id] = (now, message_hash)

                # Check 2: Similar notification type detection (e.g., multiple TPMS warnings)
                # This catches cases like FL, FR, RL, RR TPMS warnings flooding in rapid succession
                if cache_key in self._last_notification_type_cache:
                    last_type_time, last_type_key = self._last_notification_type_cache[cache_key]
                    if (now - last_type_time < self.SIMILAR_NOTIFICATION_WINDOW_SECONDS):
                        logger.info(
                            f"MQTT Notify: Suppressing similar notification for vehicle '{vehicle_id}' "
                            f"(type: {notification_key}, last similar notification {now - last_type_time:.1f}s ago, "
                            f"window: {self.SIMILAR_NOTIFICATION_WINDOW_SECONDS}s). Message: '{message_plain[:80]}...'"
                        )
                        return
                self._last_notification_type_cache[cache_key] = (now, notification_key)

            alert_type_char_map = {'alert': 'A', 'warn': 'W', 'info': 'I', 'error': 'E'}
            ntfy_priority_map = {'alert': 4, 'warn': 3, 'info': 2, 'error': 4}

            alert_type_char = alert_type_char_map.get(notification_type, 'I')
            ntfy_priority = ntfy_priority_map.get(notification_type, 3)

            title = f"OVMS {notification_type.capitalize()}: {vehicle_id} ({subtype})"

            logger.info(f"MQTT Notify: Received for vehicle '{vehicle_id}'. Title: '{title}', Body: '{message_plain[:100]}...'")

            # Dispatch off the paho network thread.
            #
            # This ran inline in the MQTT callback, and dispatch performs SMTP, NTFY,
            # FCM, APNs and UnifiedPush requests one after another with 10-second
            # timeouts each. paho has a single network thread, so one slow recipient
            # stalled notifications for *every* vehicle on the server — and the NTFY
            # server URL is per-vehicle and user-supplied, so pointing it at a tarpit
            # was enough to do it deliberately. The V2 path already offloads via
            # asyncio.to_thread; this is the same idea for a non-async caller.
            #
            # The queue behind this is bounded. It was a ThreadPoolExecutor, whose queue
            # is not: when the workers could not keep up, the backlog grew silently and
            # every notification in it was delivered later than the one before, with
            # nothing in the log to say so. A bound turns that into a visible warning and
            # a bounded loss of the stalest messages.
            if not self._dispatch_pool.submit(
                self._dispatch_safely,
                vehicle_id=vehicle_id,
                title=title,
                message_plain=message_plain,
                source_protocol='v3',
                ntfy_priority=ntfy_priority,
                ntfy_tags=["v3_notification", notification_type, subtype.replace('/', '_')],
                fcm_data_payload={"notification_type": alert_type_char, "vehicle_id": vehicle_id, "v3_subtype": subtype},
                alert_type_char=alert_type_char
            ):
                # Admission was refused or displaced an older message; either way this
                # one may never be sent, so it must not hold a de-duplication slot.
                self._forget_dedup(vehicle_id)

        except Exception as e:
            logger.error(f"Error processing MQTT notification message on topic {msg.topic}: {e}", exc_info=True)

    def _handle_v3_data_record(self, vehicle_id: str, topic_parts: list, payload: str):
        """
        Stores a generic V3 history record in the historical_data table.
        Topic:   ovms/<user>/<vehicle>/notify/data/<subtype...>/<msg_id>/<-age_seconds>
        Payload: <record_type>,<record_number>,<lifetime_seconds>,<data...>
        Same convention as the V2 'h'/'H' messages; save_historical_data upserts on
        (vehicle, record_type, record_number), enforces the size and row quotas, and the
        cleanup task prunes expired records via expires_at.
        """
        fields = payload.split(',', 3)
        if len(fields) < 3 or not fields[0]:
            logger.debug(f"MQTT Notify: Dropping malformed data record for '{vehicle_id}': {payload[:80]}")
            return

        record_type = fields[0][:50]  # historical_data.record_type is String(50)
        try:
            record_number = int(fields[1])
            lifetime_seconds = int(fields[2])
        except ValueError:
            logger.debug(f"MQTT Notify: Dropping data record with non-numeric header for '{vehicle_id}': {payload[:80]}")
            return

        # The record age is published as a negative offset in the last topic segment
        timediff_seconds = 0
        try:
            timediff_seconds = min(0, int(topic_parts[-1]))
        except (ValueError, IndexError):
            pass

        data_blob = fields[3] if len(fields) == 4 else ""
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        timestamp = now_utc + datetime.timedelta(seconds=timediff_seconds)
        expires_at = now_utc + datetime.timedelta(seconds=lifetime_seconds) if lifetime_seconds > 0 else None

        db = self._SessionLocal()
        try:
            if record_type in get_record_blocklist(db):
                logger.debug(f"MQTT Notify: Data record type '{record_type}' for '{vehicle_id}' is blocklisted, dropped.")
                return
            vehicle_db = crud.vehicle.get_vehicle_by_vehicle_id(db, vehicle_id)
            if not vehicle_db:
                logger.debug(f"MQTT Notify: Data record for unknown vehicle '{vehicle_id}', dropped.")
                return
            # allow_update=False: the record number of the session logs (*-LOG-Trip etc.)
            # is a constant format version, not a unique key - upserting on it would
            # overwrite the previous session instead of building a history
            crud.historical_data.save_historical_data(
                db, vehicle_db,
                data_payload=data_blob,
                record_type=record_type,
                record_number=record_number,
                timestamp=timestamp,
                expires_at=expires_at,
                allow_update=False
            )
            logger.debug(f"MQTT Notify: Stored data record '{record_type}' #{record_number} for '{vehicle_id}'.")
        except Exception as e:
            logger.error(f"Error saving V3 data record for {vehicle_id}: {e}", exc_info=True)
        finally:
            db.close()

    def _handle_v3_debug_data(self, vehicle_id: str, debug_name: str, record_number: int, timediff_seconds: int, payload: str):
        logger.info(f"MQTT Notify: Received V3 debug data '{debug_name}' for '{vehicle_id}', record #{record_number}")
        db = self._SessionLocal()
        try:
            vehicle_db = crud.vehicle.get_vehicle_by_vehicle_id(db, vehicle_id)
            if not vehicle_db:
                logger.warning(f"Received V3 debug data for unknown vehicle: {vehicle_id}")
                return

            payload_parts = payload.split(',', 3)
            if len(payload_parts) == 4:
                data_blob = payload_parts[3]
                try:
                    lifetime_seconds = int(payload_parts[2])
                except ValueError:
                    lifetime_seconds = 0
            else:
                data_blob = payload
                lifetime_seconds = 0

            now_utc = datetime.datetime.now(datetime.timezone.utc)
            timestamp = now_utc + datetime.timedelta(seconds=timediff_seconds) if timediff_seconds != 0 else now_utc
            expires_at = now_utc + datetime.timedelta(seconds=lifetime_seconds) if lifetime_seconds > 0 else None

            crud.historical_data.save_historical_data(
                db, vehicle_db,
                data_payload=data_blob,
                record_type=f"V3Debug-{debug_name}-{record_number}",
                record_number=record_number,
                timestamp=timestamp,
                expires_at=expires_at
            )
        except Exception as e:
            logger.error(f"Error saving V3 debug data for {vehicle_id}: {e}", exc_info=True)
        finally:
            db.close()

    def _handle_v3_crash_log(self, vehicle_id: str, record_number: int, timediff_seconds: int, payload: str):
        logger.info(f"MQTT Notify: Received V3 crash log for '{vehicle_id}', record #{record_number}")
        db = self._SessionLocal()
        try:
            vehicle_db = crud.vehicle.get_vehicle_by_vehicle_id(db, vehicle_id)
            if not vehicle_db:
                logger.warning(f"Received V3 crash log for unknown vehicle: {vehicle_id}")
                return

            payload_parts = payload.split(',', 3)
            if len(payload_parts) == 4 and payload_parts[0] == "*-OVM-DebugCrash":
                lifetime_seconds = int(payload_parts[2])
                data_blob = payload_parts[3]
                
                now_utc = datetime.datetime.now(datetime.timezone.utc)
                timestamp = now_utc + datetime.timedelta(seconds=timediff_seconds)
                expires_at = now_utc + datetime.timedelta(seconds=lifetime_seconds) if lifetime_seconds > 0 else None
                
                crud.historical_data.save_historical_data(
                    db, vehicle_db,
                    data_payload=data_blob,
                    record_type=f"V3Crash-{record_number}",
                    record_number=record_number,
                    timestamp=timestamp,
                    expires_at=expires_at
                )
            else:
                logger.warning(f"Unrecognized V3 crash log payload format for {vehicle_id}: {payload[:100]}")
        finally:
            db.close()

    def stats(self) -> dict:
        """Queue depths for the admin diagnostics endpoint.

        This is the number to look at when notifications are arriving late: a non-zero
        `queued` that does not fall, or a rising `dropped`, says which of the two stages
        is behind — and they fail for entirely different reasons.
        """
        return {"dispatch": self._dispatch_pool.stats(), "data": self._data_pool.stats()}

    def disconnect(self):
        if self._client:
            self._client.loop_stop()
            self._client.disconnect()
            logger.info("MQTT Notification Subscriber disconnected.")
        # Let queued work finish rather than dropping it on shutdown. The history records
        # get the longer drain of the two: a lost notification is a missed alert, a lost
        # record is a hole in the vehicle's history that nothing will fill in later.
        self._data_pool.shutdown(drain_timeout=20.0)
        self._dispatch_pool.shutdown(drain_timeout=10.0)

mqtt_notification_subscriber = MqttNotificationSubscriber()