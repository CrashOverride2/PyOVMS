import paho.mqtt.client as mqtt
import logging
import datetime
import threading
import time
from typing import Optional
from sqlalchemy.orm import sessionmaker

from app.config import settings
from app import crud
from app.database import engine
from app.metrics_manager import metrics_manager
from app.utils import mqtt_topic_auth
from app.services.charge_logger.charge_manager import charge_manager
from app.services.event_logger.event_manager import event_manager
logger = logging.getLogger(__name__)

class MqttMetricsSubscriber:
    """Listens to the MQTT broker for vehicle metrics and updates the DB."""

    LAST_SEEN_WRITE_INTERVAL_SECONDS = 30

    # How far the vehicle's own clock may differ from ours before we stop believing
    # it. Real modules drift by seconds; anything past this is a broken clock or a
    # forged value, and both are better served by server time.
    MAX_VEHICLE_CLOCK_SKEW_SECONDS = 300

    # How long a measured clock offset stays usable. A module's offset is a slow
    # property -- a few seconds, drifting over days -- so this only has to outlast the
    # idle publish interval of the quietest module.
    CLOCK_OFFSET_TTL_SECONDS = 3600

    # A broken clock stays broken and the module republishes it on every wake-up, so
    # the warning is rate limited per vehicle. It says the same thing the tenth time.
    CLOCK_WARNING_INTERVAL_SECONDS = 3600

    EVENT_TOPIC = "ovms/+/+/event/#"
    EVENT_RESUBSCRIBE_SECONDS = 60

    def __init__(self):
        self._client: mqtt.Client = None
        self._metric_subscribe_mid: Optional[int] = None
        # At most one retry of the event subscription pending: one per refusal would
        # start a further chain on every reconnect, each asking every minute.
        self._event_retry: Optional[threading.Timer] = None
        self._event_retry_lock = threading.Lock()
        self._SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        # Vehicle/owner resolution is memoised in app.utils.mqtt_topic_auth so both
        # subscribers share one cache and one authorization rule.
        # Monotonic seconds, not wall clock: the throttle must not be steerable by a
        # payload-derived timestamp, and it must survive a system clock adjustment.
        self._last_seen_write_at: dict[str, float] = {}
        # (offset_seconds, monotonic_measured_at) per vehicle, written only when an
        # m.time.utc message actually arrives -- see _resolve_timestamp.
        self._clock_offsets: dict[str, tuple[float, float]] = {}
        self._clock_warned_at: dict[str, float] = {}

    def connect(self, username: str, password: str):
        if not settings.MQTT_BROKER_HOST:
            logger.warning("MQTT Metrics Subscriber disabled: Broker host not configured.")
            return

        self._client = mqtt.Client(client_id="pyovms_metrics_subscriber")
        self._client.username_pw_set(username, password)

        self._client.on_connect = self._on_connect
        self._client.on_subscribe = self._on_subscribe
        self._client.on_message = self._on_message
        self._client.on_disconnect = self._on_disconnect

        try:
            self._client.connect(settings.MQTT_BROKER_HOST, settings.MQTT_BROKER_PORT, 60)
            self._client.loop_start()
        except Exception as e:
            logger.error(f"MQTT Metrics Subscriber failed to connect: {e}", exc_info=True)

    def _on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            logger.info("MQTT Metrics Subscriber connected to broker.")
            topic = "ovms/+/+/metric/#"
            # On paho's own thread, as its SUBACK: known before that is handled.
            _, self._metric_subscribe_mid = client.subscribe(topic)
            logger.info(f"Subscribed to MQTT topic: {topic}")
            # The module's events, for the vehicle event log: `…/event` (the legacy
            # topic, the name as payload) and `…/event/<name>` — `#` matches both.
            self._subscribe_events(client)
        else:
            logger.error(f"MQTT Metrics Subscriber connection failed with code {rc}")

    def _subscribe_events(self, client):
        client.subscribe(self.EVENT_TOPIC)
        logger.info(f"Subscribing to MQTT topic: {self.EVENT_TOPIC}")

    def _on_subscribe(self, client, userdata, mid, granted_qos):
        """The event topic is a later addition to this account's ACL. A broker that
        checks a SUBSCRIBE against an ACL not yet rewritten refuses it (0x80), and
        nothing would ask again before the next reconnect — the metrics still flow, so
        the event path would be silently dead. A refusal is retried until granted."""
        # Anything but the metric subscription is the event topic's (a retry's SUBACK may
        # arrive before its mid is known).
        if mid == self._metric_subscribe_mid:
            return
        if any(int(q) >= 0x80 for q in granted_qos):
            logger.warning(
                f"Broker refused {self.EVENT_TOPIC}; retrying in "
                f"{self.EVENT_RESUBSCRIBE_SECONDS}s. The account needs "
                f"'topic read {self.EVENT_TOPIC}' in the ACL.")
            with self._event_retry_lock:
                if self._event_retry is not None:
                    return
                timer = threading.Timer(self.EVENT_RESUBSCRIBE_SECONDS, self._retry_event_subscribe, args=(client,))
                timer.daemon = True
                self._event_retry = timer
            timer.start()
        else:
            logger.info(f"Subscribed to MQTT topic: {self.EVENT_TOPIC}")

    def _cancel_event_retry(self):
        with self._event_retry_lock:
            timer, self._event_retry = self._event_retry, None
        if timer is not None:
            timer.cancel()

    def _retry_event_subscribe(self, client):
        with self._event_retry_lock:
            self._event_retry = None
        if client is self._client and client.is_connected():
            self._subscribe_events(client)

    def _on_disconnect(self, client, userdata, rc):
        # The reconnect subscribes afresh.
        self._cancel_event_retry()
        if rc == 0:
            logger.info("MQTT Metrics Subscriber disconnected cleanly.")
        else:
            logger.warning(f"MQTT Metrics Subscriber disconnected unexpectedly with code {rc}.")

    def _on_message(self, client, userdata, msg):
        try:
            parts = msg.topic.split('/')
            if len(parts) >= 4 and parts[3] == 'event':
                self._on_event(msg, parts)
                return
            if len(parts) < 5 or parts[3] != 'metric':
                return

            topic_username = parts[1]
            vehicle_id = parts[2].upper()

            # The broker only restricts the topic *prefix* an account may publish under,
            # so the owner segment must be checked against the DB here — otherwise any
            # user with an API key can write metrics into someone else's vehicle.
            if not mqtt_topic_auth.topic_owner_matches(self._SessionLocal, topic_username, vehicle_id):
                return

            metric_name = ".".join(parts[4:])
            if not metric_name or len(parts) > 12:
                logger.debug(f"Dropping metric with excessive topic depth or empty name on {msg.topic}")
                return
            try:
                metric_value = msg.payload.decode('utf-8').strip()
            except UnicodeDecodeError:
                logger.debug(f"Skipping non-UTF-8 payload on topic {msg.topic}")
                return

            # Normalize empty strings to None for consistent handling
            # Empty strings can't be converted to float and cause crashes
            if metric_value == '':
                metric_value = None

            metric_changed = metrics_manager.update_metric(vehicle_id, metric_name, metric_value)

            now_utc = datetime.datetime.now(datetime.timezone.utc)
            timestamp = self._resolve_timestamp(
                vehicle_id, metric_name, metric_value, msg.retain, now_utc
            )

            if metric_changed or not msg.retain:
                # Retained is passed on: its value is the module's last publish, its
                # arrival after a restart is not when that happened, and a session
                # resumed from it must not be dated by it.
                charge_manager.process_metric(
                    vehicle_id, metric_name, metric_value, timestamp, retained=msg.retain
                )
                try:
                    event_manager.process_metric(
                        vehicle_id, metric_name, metric_value, timestamp, retained=msg.retain
                    )
                except Exception as e:
                    # The event log is an addition: its failure must not cost this
                    # message its `last_seen_v3` update below.
                    logger.error(f"Vehicle event log failed on {msg.topic}: {e}", exc_info=True)

            if msg.retain:
                if metric_changed:
                    logger.debug(f"Ignoring last_seen_v3 update for retained message on topic {msg.topic}")
                return

            # Throttle on the server clock, never on the payload-derived timestamp: the
            # latter is partly vehicle-controlled, and a future value would hold the
            # throttle open indefinitely.
            last_write_at = self._last_seen_write_at.get(vehicle_id)
            if last_write_at is not None and (time.monotonic() - last_write_at) < self.LAST_SEEN_WRITE_INTERVAL_SECONDS:
                return

            db = self._SessionLocal()
            try:
                # Through the CRUD function, not a direct column write: it also clears
                # unused_reminder_sent_at. Written directly, a V3-only vehicle that came
                # back after the 365-day warning kept its mark — the auto-deletion
                # itself re-checks last_seen and spared it, but the next time it went
                # quiet for a year it was deleted on the spot, with no second warning.
                vehicle_db = crud.vehicle.update_vehicle_last_seen_v3(db, vehicle_id, timestamp)
                if not vehicle_db:
                    mqtt_topic_auth.clear_cache()
                    return

                self._last_seen_write_at[vehicle_id] = time.monotonic()
                logger.debug(f"Updated last_seen_v3 for vehicle '{vehicle_id}' to {timestamp} based on metric '{metric_name}'")
            finally:
                db.close()
                
        except Exception as e:
            logger.error(f"Error processing MQTT metric message on topic {msg.topic}: {e}", exc_info=True)

    def _on_event(self, msg, parts):
        """One module event, from either of its topics: `ovms/<user>/<id>/event` with
        the name as payload (legacy), or `ovms/<user>/<id>/event/<name with />` with an
        empty one. The event manager drops the second copy of the same event."""
        if msg.retain or len(parts) > 16:
            return
        topic_username = parts[1]
        vehicle_id = parts[2].upper()
        if len(parts) == 4:
            if len(msg.payload) > 128:
                return
            try:
                event_name = msg.payload.decode('utf-8').strip()
            except UnicodeDecodeError:
                return
        else:
            event_name = ".".join(parts[4:])
        if not event_name or len(event_name) > 128:
            return
        # Before the owner check: a DB round trip per event of a fleet is not spent on
        # the hundreds of event names nothing here records.
        if not event_manager.wants_event(event_name):
            return
        if not mqtt_topic_auth.topic_owner_matches(self._SessionLocal, topic_username, vehicle_id):
            return
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        timestamp = self._resolve_timestamp(vehicle_id, event_name, None, False, now_utc)
        event_manager.process_event(vehicle_id, event_name, timestamp)

    def _resolve_timestamp(
        self,
        vehicle_id: str,
        metric_name: str,
        metric_value,
        retained: bool,
        now_utc: datetime.datetime,
    ) -> datetime.datetime:
        """
        Decide which clock stamps this metric.

        Server time is the arrival time and is always available; the vehicle's clock is
        only ever used as a *correction* to it, measured at the moment `m.time.utc`
        itself arrives. Reading the cached `m.time.utc` for every metric -- which is
        what this used to do -- stamped a message that arrived now with the module's
        clock reading from its previous wake-up. An idle module publishes its changed
        metrics in one burst every 5-10 minutes, so that reading was a whole publish
        interval old: silently accepted whenever it happened to fall inside the
        plausibility window, and otherwise logged once per message in the burst -- 21
        identical lines claiming a healthy module was 601s out.

        This timestamp drives last_seen_v3 (the online indicator), last_message_at and
        the start/end times of charge sessions, so getting it from the arrival of the
        message rather than from a cache is the point.
        """
        if metric_name == "m.time.utc":
            # A retained value is old by definition and its age is unknowable, so it
            # can neither measure an offset nor evidence a broken clock.
            if retained:
                return now_utc

            vehicle_timestamp = self._parse_vehicle_clock(vehicle_id, metric_value)
            if vehicle_timestamp is None:
                return now_utc

            skew = (vehicle_timestamp - now_utc).total_seconds()
            if abs(skew) > self.MAX_VEHICLE_CLOCK_SKEW_SECONDS:
                # Unchecked, `m.time.utc = 9999-01-01` pinned the car "online" forever,
                # so connection-loss alerts never fired, and the write throttle below
                # (which compared against the same value) suppressed every later
                # update. A clock that far out is wrong whatever the cause.
                self._clock_offsets.pop(vehicle_id, None)
                self._warn_about_clock(vehicle_id, vehicle_timestamp, skew)
                return now_utc

            self._clock_offsets[vehicle_id] = (skew, time.monotonic())
            return vehicle_timestamp

        measured = self._clock_offsets.get(vehicle_id)
        if measured is None:
            return now_utc

        offset_seconds, measured_at = measured
        if (time.monotonic() - measured_at) > self.CLOCK_OFFSET_TTL_SECONDS:
            del self._clock_offsets[vehicle_id]
            return now_utc

        return now_utc + datetime.timedelta(seconds=offset_seconds)

    @staticmethod
    def _parse_vehicle_clock(vehicle_id: str, raw_value) -> datetime.datetime | None:
        """Parse the module's clock reading, format '2025-10-29 19:35:30 UTC'."""
        if not raw_value:
            return None
        try:
            time_str = str(raw_value).strip()
            if time_str.endswith(' UTC'):
                time_str = time_str[:-4].strip()
            return datetime.datetime.strptime(time_str, '%Y-%m-%d %H:%M:%S').replace(
                tzinfo=datetime.timezone.utc
            )
        except (ValueError, TypeError) as e:
            logger.debug(f"Could not parse m.time.utc for vehicle {vehicle_id}: {e}")
            return None

    def _warn_about_clock(
        self, vehicle_id: str, vehicle_timestamp: datetime.datetime, skew: float
    ) -> None:
        now = time.monotonic()
        warned_at = self._clock_warned_at.get(vehicle_id)
        if warned_at is not None and (now - warned_at) < self.CLOCK_WARNING_INTERVAL_SECONDS:
            return
        self._clock_warned_at[vehicle_id] = now
        logger.warning(
            f"Ignoring implausible m.time.utc for vehicle '{vehicle_id}': "
            f"{vehicle_timestamp.isoformat()} is {abs(skew):.0f}s from server time; "
            f"using server time instead."
        )

    def disconnect(self):
        self._cancel_event_retry()
        if self._client:
            self._client.loop_stop()
            self._client.disconnect()
            logger.info("MQTT Metrics Subscriber disconnected.")

mqtt_metrics_subscriber = MqttMetricsSubscriber()
